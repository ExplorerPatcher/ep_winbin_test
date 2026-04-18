using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Glue
{
    internal static class MonitorConstants
    {
        public static string WorkerExePath/* = "ep_winbin_test_worker.exe"*/;
        public const string WorkerResultsRoot = "WorkerResults";
        public const string ManifestDbPath = "WinbindexMonitor.sqlite";
        public const string DiscordWebhookUrl = ""; // TODO Make use of .env
        public static readonly TimeSpan PollInterval = TimeSpan.FromHours(1);
    }

    internal static class ProgramMonitorExtensions
    {
        public static async Task<int> RunMonitorOnceAsync(IReadOnlyList<DownloadDefinition> definitions, string outputRoot)
        {
            Directory.CreateDirectory(outputRoot);
            Directory.CreateDirectory(MonitorConstants.WorkerResultsRoot);

            using (var repo = new ManifestRepository(MonitorConstants.ManifestDbPath))
            {
                repo.Initialize();

                var service = new MonitorService(definitions, outputRoot, repo);
                await service.RunOnceAsync().ConfigureAwait(false);
            }

            return 0;
        }

        public static async Task<int> RunMonitorLoopAsync(IReadOnlyList<DownloadDefinition> definitions, string outputRoot, CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(outputRoot);
            Directory.CreateDirectory(MonitorConstants.WorkerResultsRoot);

            using (var repo = new ManifestRepository(MonitorConstants.ManifestDbPath))
            {
                repo.Initialize();
                var service = new MonitorService(definitions, outputRoot, repo);

                while (!cancellationToken.IsCancellationRequested)
                {
                    var cycleStartUtc = DateTime.UtcNow;
                    await service.RunOnceAsync().ConfigureAwait(false);

                    var nextUtc = cycleStartUtc + MonitorConstants.PollInterval;
                    var delay = nextUtc - DateTime.UtcNow;
                    if (delay > TimeSpan.Zero)
                        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }

            return 0;
        }
    }

    internal sealed class MonitorService
    {
        private readonly IReadOnlyList<DownloadDefinition> _definitions;
        private readonly string _outputRoot;
        private readonly ManifestRepository _repo;
        private readonly Downloader _downloader;
        private readonly WorkerInvoker _workerInvoker;
        private readonly DiscordWebhookPublisher _discordPublisher;

        public MonitorService(IReadOnlyList<DownloadDefinition> definitions, string outputRoot, ManifestRepository repo)
        {
            _definitions = definitions;
            _outputRoot = outputRoot;
            _repo = repo;
            _downloader = new Downloader(maxParallelism: 8, outputRoot: outputRoot);
            _workerInvoker = new WorkerInvoker();
            _discordPublisher = new DiscordWebhookPublisher(MonitorConstants.DiscordWebhookUrl);
        }

        public async Task RunOnceAsync()
        {
            // todo make this configurable
            MonitorConstants.WorkerExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ep_winbin_test_worker.exe");
            if (!File.Exists(MonitorConstants.WorkerExePath))
            {
                throw new FileNotFoundException("Worker executable not found at expected path: " + MonitorConstants.WorkerExePath);
            }

            string currentWorkerSha256 = ComputeSha256Hex(MonitorConstants.WorkerExePath);
            string previousWorkerSha256 = _repo.GetAppState("worker_sha256");
            if (!string.IsNullOrEmpty(currentWorkerSha256) && !string.Equals(previousWorkerSha256, currentWorkerSha256, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Worker executable changed, running full worker.");
                await RunFullWorkerIfChangedAsync(currentWorkerSha256).ConfigureAwait(false);
                _repo.SetAppState("worker_sha256", currentWorkerSha256);
            }
            else
            {
                Console.WriteLine("Worker executable unchanged.");
            }

            Console.WriteLine("Fetching from Winbindex...");
            var allCandidates = new List<DownloadCandidate>();
            foreach (var definition in _definitions)
            {
                var candidates = await WinbindexClient.EnumerateCandidatesFromAllSourcesAsync(definition).ConfigureAwait(false);
                allCandidates.AddRange(candidates);
            }

            _repo.EvictStaleBinaries();

            var newlyDiscovered = new List<MonitoredBinary>();
            foreach (var candidate in allCandidates)
            {
                if (_repo.TryInsertDiscoveredBinary(candidate, _outputRoot, out var inserted))
                    newlyDiscovered.Add(inserted);
            }

            if (newlyDiscovered.Count == 0)
            {
                Console.WriteLine("No new binaries discovered.");
                return;
            }

            var downloadable = newlyDiscovered
                .Where(x => x.Status == ManifestStatus.Discovered)
                .ToList();

            if (downloadable.Count == 0)
            {
                Console.WriteLine("No new binaries to download.");
                return;
            }

            Console.WriteLine($"Attempting to download {downloadable.Count} binaries...");
            var downloadedThisRun = new List<MonitoredBinary>();
            var candidateToBinaryMap = new Dictionary<DownloadCandidate, MonitoredBinary>();
            foreach (var binary in downloadable)
            {
                candidateToBinaryMap[binary.Candidate] = binary;
            }
            await _downloader.DownloadAllAsync(
                downloadable.Select(x => x.Candidate).ToList(),
                shouldSkipCandidate: _repo.ShouldSkipRetry,
                onCompleted: (candidate, result) =>
                {
                    var binary = candidateToBinaryMap[candidate];
                    if (result.Success)
                    {
                        binary.LocalPath = result.FullOutputPath;
                        binary.SymbolUrl = result.UsedUrl;
                        binary.Status = ManifestStatus.Downloaded;
                        binary.DownloadedUtc = DateTime.UtcNow;
                        _repo.MarkBinaryDownloaded(binary);
                        downloadedThisRun.Add(binary);
                    }
                    else if (result.ShouldNeverRetry)
                    {
                        _repo.MarkBinaryFailedDueToNoWorkingURLs(binary);
                    }
                    else
                    {
                        _repo.DeleteBinary(binary);
                    }
                }
            ).ConfigureAwait(false);

            if (downloadedThisRun.Count == 0)
            {
                Console.WriteLine("No new binaries downloaded successfully.");
                return;
            }

            // Get real assembly version for each binary
            foreach (var binary in downloadedThisRun)
            {
                if (FileVersionReader.TryReadVersionInfo(binary.LocalPath, out _, out var fileVersion))
                {
                    binary.RealAssemblyVersion = fileVersion;
                }
            }

            var versionsStr = DiscordWebhookPublisher.FormatVersionListDescending(downloadedThisRun.Select(x => x.RealAssemblyVersion.ToString()), 20);
            Console.WriteLine($"Running worker on {downloadedThisRun.Count} new binaries with versions {versionsStr}...");
            string resultBaseName = MakeResultBaseNameUtc();
            var workerRun = _workerInvoker.RunIncremental(resultBaseName, downloadedThisRun.Select(x => Path.GetFullPath(x.LocalPath)).ToList());
            _repo.InsertWorkerRun(workerRun, currentWorkerSha256);

            if (!workerRun.Success || string.IsNullOrEmpty(workerRun.JsonPath) || !File.Exists(workerRun.JsonPath))
            {
                Console.WriteLine("Worker run failed or did not produce results.");
                return;
            }

            var parsed = WorkerResultParser.Parse(workerRun.JsonPath);
            _repo.SaveWorkerResults(workerRun, parsed);
            _repo.MarkAnalyzed(downloadedThisRun, workerRun.ResultBaseName);

            await PublishForNewDownloadsAsync(downloadedThisRun, parsed, workerRun).ConfigureAwait(false);
        }

        private async Task RunFullWorkerIfChangedAsync(string workerSha256)
        {
            if (!File.Exists(MonitorConstants.WorkerExePath))
                return;

            string resultBaseName = MakeResultBaseNameUtc();
            var workerRun = _workerInvoker.RunFull(resultBaseName);
            _repo.InsertWorkerRun(workerRun, workerSha256);
            if (!workerRun.Success || string.IsNullOrEmpty(workerRun.JsonPath) || !File.Exists(workerRun.JsonPath))
            {
                Console.WriteLine("Nothing to publish from full worker run.");
                return;
            }

            var parsed = WorkerResultParser.Parse(workerRun.JsonPath);
            _repo.SaveWorkerResults(workerRun, parsed);
            await _discordPublisher.PublishFullRunAsync(parsed, workerRun).ConfigureAwait(false);
        }

        private async Task PublishForNewDownloadsAsync(IReadOnlyList<MonitoredBinary> downloadedThisRun, ParsedWorkerRun parsed, WorkerRunResult workerRun)
        {
            if (downloadedThisRun.Count >= 10)
            {
                await _discordPublisher.PublishAggregateAsync(downloadedThisRun, parsed, workerRun).ConfigureAwait(false);
                _repo.MarkPublished(downloadedThisRun);
                return;
            }

            var groups = downloadedThisRun
                .GroupBy(MakePublishGroupKey, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var group in groups)
            {
                var groupList = group.ToList();
                await _discordPublisher.PublishSingleUpdateGroupAsync(groupList, parsed, workerRun).ConfigureAwait(false);
                _repo.MarkPublished(groupList);
            }
        }

        private static string MakePublishGroupKey(MonitoredBinary binary)
        {
            if (!string.IsNullOrWhiteSpace(binary.UpdateHeading))
                return binary.UpdateHeading;
            if (!string.IsNullOrWhiteSpace(binary.UpdateTitle))
                return binary.UpdateTitle;
            return binary.RealAssemblyVersion.ToString();
        }

        private static string ComputeSha256Hex(string path)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(path))
            {
                byte[] hash = sha256.ComputeHash(stream);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                    sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private static string MakeResultBaseNameUtc()
        {
            return "results-" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ssZ", CultureInfo.InvariantCulture);
        }
    }

    internal enum ManifestStatus
    {
        Discovered = 0,
        Downloaded = 1,
        CandidateFailed = 2,
        Analyzed = 3,
        Published = 4,
    }

    internal sealed class MonitoredBinary
    {
        public long Id { get; set; }
        public DownloadCandidate Candidate { get; set; }
        public string LocalPath { get; set; }
        public string SymbolUrl { get; set; }
        public string UpdateHeading { get; set; }
        public string UpdateTitle { get; set; }
        public string UpdateReleaseDate { get; set; }
        public string UpdateReleaseVersion { get; set; }
        public string UpdateUrl { get; set; }
        public string InsiderBuild { get; set; }
        public DateTime? InsiderCreatedUtc { get; set; }
        public ManifestStatus Status { get; set; }
        public DateTime? DownloadedUtc { get; set; }

        public Version RealAssemblyVersion { get; set; }
    }

    internal sealed class ManifestRepository : IDisposable
    {
        private readonly SQLiteConnection _connection;

        public ManifestRepository(string databasePath)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(databasePath)));
            _connection = new SQLiteConnection("Data Source=" + databasePath + ";Version=3;");
            _connection.Open();
        }

        public void Initialize()
        {
            ExecuteNonQuery(@"
CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS binary_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_name TEXT NOT NULL,
    machine_type INTEGER NOT NULL,
    source TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    assembly_version TEXT NOT NULL,
    local_path TEXT NULL,
    symbol_url TEXT NULL,
    update_heading TEXT NULL,
    update_title TEXT NULL,
    update_release_date TEXT NULL,
    update_release_version TEXT NULL,
    update_url TEXT NULL,
    insider_build TEXT NULL,
    insider_created_utc TEXT NULL,
    discovered_utc TEXT NOT NULL,
    downloaded_utc TEXT NULL,
    analyzed_utc TEXT NULL,
    published_utc TEXT NULL,
    status TEXT NOT NULL,
    worker_result_base_name TEXT NULL,
    fail_reason TEXT NULL,
    UNIQUE(module_name, machine_type, source, file_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_binary_record_identity
ON binary_record(module_name, machine_type, source, file_hash);

CREATE TABLE IF NOT EXISTS worker_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_base_name TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    worker_sha256 TEXT NOT NULL,
    input_list_path TEXT NULL,
    result_json_path TEXT NULL,
    result_html_path TEXT NULL,
    started_utc TEXT NOT NULL,
    finished_utc TEXT NULL,
    success INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS worker_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_run_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    version TEXT NOT NULL,
    statuses_json TEXT NOT NULL,
    UNIQUE(worker_run_id, module_name, version)
);
");
        }

        public string GetAppState(string key)
        {
            using (var cmd = new SQLiteCommand("SELECT value FROM app_state WHERE key=@key;", _connection))
            {
                cmd.Parameters.AddWithValue("@key", key);
                object value = cmd.ExecuteScalar();
                return value == null || value == DBNull.Value ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
            }
        }

        public void SetAppState(string key, string value)
        {
            using (var cmd = new SQLiteCommand(@"INSERT INTO app_state(key, value) VALUES(@key, @value)
ON CONFLICT(key) DO UPDATE SET value=excluded.value;", _connection))
            {
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@value", value ?? string.Empty);
                cmd.ExecuteNonQuery();
            }
        }

        public bool TryInsertDiscoveredBinary(DownloadCandidate candidate, string outputRoot, out MonitoredBinary inserted)
        {
            inserted = null;
            using (var cmd = new SQLiteCommand(@"
INSERT OR IGNORE INTO binary_record(
    module_name, machine_type, source, file_hash, assembly_version, local_path, symbol_url,
    update_heading, update_title, update_release_date, update_release_version, update_url,
    insider_build, insider_created_utc, discovered_utc, status)
VALUES(@module_name, @machine_type, @source, @file_hash, @assembly_version, @local_path, @symbol_url,
    @update_heading, @update_title, @update_release_date, @update_release_version, @update_url,
    @insider_build, @insider_created_utc, @discovered_utc, @status);
SELECT changes();", _connection))
            {
                cmd.Parameters.AddWithValue("@module_name", candidate.ModuleNameCanonical);
                cmd.Parameters.AddWithValue("@machine_type", (int)candidate.MachineType);
                cmd.Parameters.AddWithValue("@source", candidate.Source.ToString());
                cmd.Parameters.AddWithValue("@file_hash", candidate.FileHash);
                cmd.Parameters.AddWithValue("@assembly_version", candidate.AssemblyVersion.ToString());
                cmd.Parameters.AddWithValue("@local_path", DBNull.Value);
                cmd.Parameters.AddWithValue("@symbol_url", DBNull.Value);
                cmd.Parameters.AddWithValue("@update_heading", (object)candidate.UpdateHeading ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@update_title", (object)candidate.UpdateTitle ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@update_release_date", (object)candidate.UpdateReleaseDate ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@update_release_version", (object)candidate.UpdateReleaseVersion ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@update_url", (object)candidate.UpdateUrl ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@insider_build", (object)candidate.InsiderBuild ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@insider_created_utc", candidate.InsiderCreatedUtc.HasValue ? (object)candidate.InsiderCreatedUtc.Value.ToString("o", CultureInfo.InvariantCulture) : DBNull.Value);
                cmd.Parameters.AddWithValue("@discovered_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@status", nameof(ManifestStatus.Discovered));
                long changes = Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
                if (changes == 0)
                    return false;
            }

            long id = _connection.LastInsertRowId;
            inserted = new MonitoredBinary
            {
                Id = id,
                Candidate = candidate,
                LocalPath = null,
                SymbolUrl = null,
                UpdateHeading = candidate.UpdateHeading,
                UpdateTitle = candidate.UpdateTitle,
                UpdateReleaseDate = candidate.UpdateReleaseDate,
                UpdateReleaseVersion = candidate.UpdateReleaseVersion,
                UpdateUrl = candidate.UpdateUrl,
                InsiderBuild = candidate.InsiderBuild,
                InsiderCreatedUtc = candidate.InsiderCreatedUtc,
                Status = ManifestStatus.Discovered,
            };
            return true;
        }

        public void MarkBinaryDownloaded(MonitoredBinary binary)
        {
            using (var cmd = new SQLiteCommand(@"UPDATE binary_record
SET local_path=@local_path, symbol_url=@symbol_url, downloaded_utc=@downloaded_utc, status=@status
WHERE id=@id;", _connection))
            {
                cmd.Parameters.AddWithValue("@local_path", binary.LocalPath);
                cmd.Parameters.AddWithValue("@symbol_url", (object)binary.SymbolUrl ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@downloaded_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@status", nameof(ManifestStatus.Downloaded));
                cmd.Parameters.AddWithValue("@id", binary.Id);
                cmd.ExecuteNonQuery();
            }
        }

        public void MarkBinaryFailedDueToNoWorkingURLs(MonitoredBinary binary)
        {
            using (var cmd = new SQLiteCommand(@"UPDATE binary_record SET status=@status, fail_reason=@fail_reason WHERE id=@id;", _connection))
            {
                cmd.Parameters.AddWithValue("@status", nameof(ManifestStatus.CandidateFailed));
                cmd.Parameters.AddWithValue("@fail_reason", "all_candidate_links_404");
                cmd.Parameters.AddWithValue("@id", binary.Id);
                cmd.ExecuteNonQuery();
            }
        }

        public void DeleteBinary(MonitoredBinary binary)
        {
            using (var cmd = new SQLiteCommand(@"DELETE FROM binary_record WHERE id=@id;", _connection))
            {
                cmd.Parameters.AddWithValue("@id", binary.Id);
                cmd.ExecuteNonQuery();
            }
        }

        public void InsertWorkerRun(WorkerRunResult run, string workerSha256)
        {
            using (var cmd = new SQLiteCommand(@"
INSERT OR REPLACE INTO worker_run(result_base_name, mode, worker_sha256, input_list_path, result_json_path, result_html_path, started_utc, finished_utc, success)
VALUES(@result_base_name, @mode, @worker_sha256, @input_list_path, @result_json_path, @result_html_path, @started_utc, @finished_utc, @success);", _connection))
            {
                cmd.Parameters.AddWithValue("@result_base_name", run.ResultBaseName);
                cmd.Parameters.AddWithValue("@mode", run.IsFullRun ? "full" : "incremental");
                cmd.Parameters.AddWithValue("@worker_sha256", workerSha256 ?? string.Empty);
                cmd.Parameters.AddWithValue("@input_list_path", (object)run.InputListPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@result_json_path", (object)run.JsonPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@result_html_path", (object)run.HtmlPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@started_utc", run.StartedUtc.ToString("o", CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@finished_utc", run.FinishedUtc.ToString("o", CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@success", run.Success ? 1 : 0);
                cmd.ExecuteNonQuery();
            }
        }

        public void SaveWorkerResults(WorkerRunResult run, ParsedWorkerRun parsed)
        {
            long workerRunId;
            using (var findCmd = new SQLiteCommand("SELECT id FROM worker_run WHERE result_base_name=@result_base_name;", _connection))
            {
                findCmd.Parameters.AddWithValue("@result_base_name", run.ResultBaseName);
                object scalar = findCmd.ExecuteScalar();
                workerRunId = scalar == null ? 0L : Convert.ToInt64(scalar, CultureInfo.InvariantCulture);
            }

            foreach (var module in parsed.Modules)
            {
                foreach (var pair in module.VersionStatuses)
                {
                    using (var cmd = new SQLiteCommand(@"INSERT OR REPLACE INTO worker_result(worker_run_id, module_name, version, statuses_json)
VALUES(@worker_run_id, @module_name, @version, @statuses_json);", _connection))
                    {
                        cmd.Parameters.AddWithValue("@worker_run_id", workerRunId);
                        cmd.Parameters.AddWithValue("@module_name", module.ModuleNameCanonical);
                        cmd.Parameters.AddWithValue("@version", pair.Key);
                        cmd.Parameters.AddWithValue("@statuses_json", JsonConvert.SerializeObject(pair.Value));
                        cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public void MarkAnalyzed(IReadOnlyList<MonitoredBinary> binaries, string workerResultBaseName)
        {
            foreach (var binary in binaries)
            {
                using (var cmd = new SQLiteCommand(@"UPDATE binary_record SET analyzed_utc=@analyzed_utc, status=@status, worker_result_base_name=@worker_result_base_name WHERE id=@id;", _connection))
                {
                    cmd.Parameters.AddWithValue("@analyzed_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                    cmd.Parameters.AddWithValue("@status", nameof(ManifestStatus.Analyzed));
                    cmd.Parameters.AddWithValue("@worker_result_base_name", workerResultBaseName);
                    cmd.Parameters.AddWithValue("@id", binary.Id);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public void MarkPublished(IReadOnlyList<MonitoredBinary> binaries)
        {
            foreach (var binary in binaries)
            {
                using (var cmd = new SQLiteCommand(@"UPDATE binary_record SET published_utc=@published_utc, status=@status WHERE id=@id;", _connection))
                {
                    cmd.Parameters.AddWithValue("@published_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                    cmd.Parameters.AddWithValue("@status", nameof(ManifestStatus.Published));
                    cmd.Parameters.AddWithValue("@id", binary.Id);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public bool ShouldSkipRetry(DownloadCandidate candidate)
        {
            using (var cmd = new SQLiteCommand(@"
SELECT status
FROM binary_record
WHERE lower(module_name) = lower(@module_name)
  AND machine_type = @machine_type
  AND source = @source
  AND file_hash = @file_hash
LIMIT 1;", _connection))
            {
                cmd.Parameters.AddWithValue("@module_name", candidate.ModuleNameCanonical);
                cmd.Parameters.AddWithValue("@machine_type", (int) candidate.MachineType);
                cmd.Parameters.AddWithValue("@source", candidate.Source.ToString());
                cmd.Parameters.AddWithValue("@file_hash", candidate.FileHash);

                object scalar = cmd.ExecuteScalar();
                if (scalar == null || scalar == DBNull.Value)
                    return false;

                string status = Convert.ToString(scalar, CultureInfo.InvariantCulture);
                return string.Equals(status, nameof(ManifestStatus.CandidateFailed), StringComparison.OrdinalIgnoreCase);
            }
        }

        public MonitoredBinary TryGetBinary(DownloadCandidate candidate)
        {
            using (var cmd = new SQLiteCommand(@"
SELECT
    id,
    local_path,
    symbol_url,
    update_heading,
    update_title,
    update_release_date,
    update_release_version,
    update_url,
    insider_build,
    insider_created_utc,
    status,
    downloaded_utc
FROM binary_record
WHERE lower(module_name) = lower(@module_name)
  AND machine_type = @machine_type
  AND source = @source
  AND file_hash = @file_hash
LIMIT 1;", _connection))
            {
                cmd.Parameters.AddWithValue("@module_name", candidate.ModuleNameCanonical);
                cmd.Parameters.AddWithValue("@machine_type", (int) candidate.MachineType);
                cmd.Parameters.AddWithValue("@source", candidate.Source.ToString());
                cmd.Parameters.AddWithValue("@file_hash", candidate.FileHash);

                using (var reader = cmd.ExecuteReader())
                {
                    if (!reader.Read())
                        return null;

                    DateTime? insiderCreatedUtc = null;
                    if (!reader.IsDBNull(reader.GetOrdinal("insider_created_utc")))
                    {
                        if (DateTime.TryParse(reader.GetString(reader.GetOrdinal("insider_created_utc")), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
                            insiderCreatedUtc = parsed;
                    }

                    DateTime? downloadedUtc = null;
                    if (!reader.IsDBNull(reader.GetOrdinal("downloaded_utc")))
                    {
                        if (DateTime.TryParse(reader.GetString(reader.GetOrdinal("downloaded_utc")), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
                            downloadedUtc = parsed;
                    }

                    var status = ManifestStatus.Discovered;
                    if (!reader.IsDBNull(reader.GetOrdinal("status")))
                    {
                        Enum.TryParse(reader.GetString(reader.GetOrdinal("status")), ignoreCase: true, result: out status);
                    }

                    return new MonitoredBinary
                    {
                        Id = reader.GetInt64(reader.GetOrdinal("id")),
                        Candidate = candidate,
                        LocalPath = reader.IsDBNull(reader.GetOrdinal("local_path")) ? null : reader.GetString(reader.GetOrdinal("local_path")),
                        SymbolUrl = reader.IsDBNull(reader.GetOrdinal("symbol_url")) ? null : reader.GetString(reader.GetOrdinal("symbol_url")),
                        UpdateHeading = reader.IsDBNull(reader.GetOrdinal("update_heading")) ? null : reader.GetString(reader.GetOrdinal("update_heading")),
                        UpdateTitle = reader.IsDBNull(reader.GetOrdinal("update_title")) ? null : reader.GetString(reader.GetOrdinal("update_title")),
                        UpdateReleaseDate = reader.IsDBNull(reader.GetOrdinal("update_release_date")) ? null : reader.GetString(reader.GetOrdinal("update_release_date")),
                        UpdateReleaseVersion = reader.IsDBNull(reader.GetOrdinal("update_release_version")) ? null : reader.GetString(reader.GetOrdinal("update_release_version")),
                        UpdateUrl = reader.IsDBNull(reader.GetOrdinal("update_url")) ? null : reader.GetString(reader.GetOrdinal("update_url")),
                        InsiderBuild = reader.IsDBNull(reader.GetOrdinal("insider_build")) ? null : reader.GetString(reader.GetOrdinal("insider_build")),
                        InsiderCreatedUtc = insiderCreatedUtc,
                        Status = status,
                        DownloadedUtc = downloadedUtc,
                    };
                }
            }
        }

        private void ExecuteNonQuery(string sql)
        {
            using (var cmd = new SQLiteCommand(sql, _connection))
                cmd.ExecuteNonQuery();
        }

        public void Dispose()
        {
            _connection.Dispose();
        }

        public void EvictStaleBinaries()
        {
            using (var cmd = new SQLiteCommand(@"DELETE FROM binary_record WHERE status = @discovered_status;", _connection))
            {
                cmd.Parameters.AddWithValue("@discovered_status", nameof(ManifestStatus.Discovered));
                cmd.ExecuteNonQuery();
            }
        }
    }

    internal sealed class WorkerRunResult
    {
        public string ResultBaseName { get; set; }
        public string InputListPath { get; set; }
        public string JsonPath { get; set; }
        public string HtmlPath { get; set; }
        public int ExitCode { get; set; }
        public bool IsFullRun { get; set; }
        public DateTime StartedUtc { get; set; }
        public DateTime FinishedUtc { get; set; }
        public bool Success => ExitCode == 0;
    }

    internal sealed class WorkerInvoker
    {
        public WorkerRunResult RunIncremental(string resultBaseName, IReadOnlyList<string> absoluteDllPaths)
        {
            Directory.CreateDirectory(MonitorConstants.WorkerResultsRoot);
            string inputListPath = Path.Combine(MonitorConstants.WorkerResultsRoot, resultBaseName + ".txt");
            File.WriteAllLines(inputListPath, absoluteDllPaths);

            var psi = new ProcessStartInfo
            {
                FileName = MonitorConstants.WorkerExePath,
                Arguments = "incremental --input-list " + Quote(inputListPath) + " --result-base " + Quote(resultBaseName),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Directory.GetCurrentDirectory(),
            };

            var run = RunProcess(psi, resultBaseName, inputListPath, false);
            if (string.IsNullOrEmpty(run.JsonPath))
                throw new InvalidOperationException("Worker did not produce a JSON results file at the expected path: " + Path.Combine(MonitorConstants.WorkerResultsRoot, resultBaseName + ".json"));
            return run;
        }

        public WorkerRunResult RunFull(string resultBaseName)
        {
            Directory.CreateDirectory(MonitorConstants.WorkerResultsRoot);
            string binaryCacheDir = Path.Combine(Directory.GetCurrentDirectory(), "BinaryCache");

            var psi = new ProcessStartInfo
            {
                FileName = MonitorConstants.WorkerExePath,
                Arguments = "full --dir " + Quote(binaryCacheDir) + " --result-base " + Quote(resultBaseName),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Directory.GetCurrentDirectory(),
            };

            return RunProcess(psi, resultBaseName, null, true);
        }

        private WorkerRunResult RunProcess(ProcessStartInfo psi, string resultBaseName, string inputListPath, bool isFullRun)
        {
            var result = new WorkerRunResult
            {
                ResultBaseName = resultBaseName,
                InputListPath = inputListPath,
                IsFullRun = isFullRun,
                StartedUtc = DateTime.UtcNow,
            };

            using (var process = Process.Start(psi))
            {
                process.WaitForExit();
                result.ExitCode = process.ExitCode;
            }

            result.FinishedUtc = DateTime.UtcNow;
            string expectedJson = Path.Combine(MonitorConstants.WorkerResultsRoot, resultBaseName + ".json");
            string expectedHtml = Path.Combine(MonitorConstants.WorkerResultsRoot, resultBaseName + ".html");
            result.JsonPath = File.Exists(expectedJson) ? expectedJson : null;
            result.HtmlPath = File.Exists(expectedHtml) ? expectedHtml : null;
            return result;
        }

        private static string Quote(string s)
        {
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }
    }

    internal sealed class ParsedWorkerRun
    {
        public List<ParsedWorkerModuleResult> Modules { get; } = new List<ParsedWorkerModuleResult>();
        public Dictionary<string /*module name*/, string[]> Legends { get; } = new Dictionary<string, string[]>();
        public double? ElapsedTimeSeconds { get; set; }
    }

    internal sealed class ParsedWorkerModuleResult
    {
        public string ModuleNameCanonical { get; set; }
        public string Architecture { get; set; } // "amd64" or "arm64"
        public Dictionary<string, int[]> VersionStatuses { get; set; }
    }

    internal static class WorkerArch
    {
        public static ushort? ParseMachineType(string arch)
        {
            switch ((arch ?? "").Trim().ToLowerInvariant())
            {
                case "amd64":
                case "x64":
                    return MachineTypes.AMD64;

                case "arm64":
                    return MachineTypes.ARM64;

                default:
                    return null;
            }
        }
    }

    internal static class WorkerResultParser
    {
        public static ParsedWorkerRun Parse(string jsonPath)
        {
            var result = new ParsedWorkerRun();

            using (var sr = File.OpenText(jsonPath))
            using (var reader = new JsonTextReader(sr))
            {
                reader.DateParseHandling = DateParseHandling.None;
                reader.FloatParseHandling = FloatParseHandling.Double;

                ExpectToken(reader, JsonToken.StartObject);

                while (reader.Read())
                {
                    if (reader.TokenType == JsonToken.EndObject)
                        break;

                    if (reader.TokenType != JsonToken.PropertyName)
                        throw new JsonException("Expected property name at root.");

                    string propertyName = (string)reader.Value;
                    if (!reader.Read())
                        throw new JsonException("Unexpected end of JSON.");

                    switch (propertyName)
                    {
                        case "modules":
                            ReadModulesObject(reader, result);
                            break;

                        case "elapsedTimeSeconds":
                            result.ElapsedTimeSeconds = ReadNullableDoubleValue(reader);
                            break;

                        default:
                            SkipValue(reader);
                            break;
                    }
                }
            }

            return result;
        }

        private static void ReadModulesObject(JsonTextReader reader, ParsedWorkerRun result)
        {
            if (reader.TokenType == JsonToken.Null)
                return;

            if (reader.TokenType != JsonToken.StartObject)
                throw new JsonException("Expected start of modules object.");

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndObject)
                    break;

                if (reader.TokenType != JsonToken.PropertyName)
                    throw new JsonException("Expected module property name.");

                string moduleName = (string)reader.Value;

                if (!reader.Read())
                    throw new JsonException("Unexpected end while reading module object.");

                ReadModuleObject(reader, result, moduleName);
            }
        }

        private static void ReadModuleObject(JsonTextReader reader, ParsedWorkerRun result, string moduleName)
        {
            if (reader.TokenType == JsonToken.Null)
                return;

            if (reader.TokenType != JsonToken.StartObject)
                throw new JsonException("Expected start of module architectures object.");

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndObject)
                    break;

                if (reader.TokenType != JsonToken.PropertyName)
                    throw new JsonException("Expected architecture property name.");

                string key = (string)reader.Value;

                if (!reader.Read())
                    throw new JsonException("Unexpected end while reading architecture object.");

                if (key == "legend")
                {
                    result.Legends[moduleName] = ReadLegendArray(reader);
                    continue;
                }

                var versionStatuses = ReadVersionStatuses(reader);

                ushort? machineType = WorkerArch.ParseMachineType(key);
                if (!machineType.HasValue)
                    continue;

                result.Modules.Add(new ParsedWorkerModuleResult
                {
                    ModuleNameCanonical = moduleName,
                    Architecture = key,
                    VersionStatuses = versionStatuses,
                });
            }
        }

        private static string[] ReadLegendArray(JsonTextReader reader)
        {
            if (reader.TokenType == JsonToken.Null)
                return Array.Empty<string>();

            if (reader.TokenType != JsonToken.StartArray)
                throw new JsonException("Expected start of legend array.");

            var values = new List<string>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndArray)
                    break;

                if (reader.TokenType != JsonToken.String)
                    throw new JsonException("Expected string legend value.");

                values.Add((string)reader.Value);
            }

            return values.ToArray();
        }

        private static Dictionary<string, int[]> ReadVersionStatuses(JsonTextReader reader)
        {
            var dict = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);

            if (reader.TokenType == JsonToken.Null)
                return dict;

            if (reader.TokenType != JsonToken.StartObject)
                throw new JsonException("Expected start of version-statuses object.");

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndObject)
                    break;

                if (reader.TokenType != JsonToken.PropertyName)
                    throw new JsonException("Expected version property name.");

                string version = (string)reader.Value;

                if (!reader.Read())
                    throw new JsonException("Unexpected end while reading status array.");

                dict[version] = ReadStatusArray(reader);
            }

            return dict;
        }

        private static int[] ReadStatusArray(JsonTextReader reader)
        {
            if (reader.TokenType == JsonToken.Null)
                return Array.Empty<int>();

            if (reader.TokenType != JsonToken.StartArray)
                throw new JsonException("Expected start of status array.");

            var values = new List<int>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndArray)
                    break;

                switch (reader.TokenType)
                {
                    case JsonToken.Integer:
                    case JsonToken.Float:
                        values.Add(Convert.ToInt32(reader.Value, CultureInfo.InvariantCulture));
                        break;

                    default:
                        throw new JsonException("Expected numeric status value.");
                }
            }

            return values.ToArray();
        }

        private static double? ReadNullableDoubleValue(JsonTextReader reader)
        {
            if (reader.TokenType == JsonToken.Null)
                return null;

            if (reader.TokenType == JsonToken.Float ||
                reader.TokenType == JsonToken.Integer)
            {
                return Convert.ToDouble(reader.Value, CultureInfo.InvariantCulture);
            }

            throw new JsonException("Expected numeric value.");
        }

        private static void ExpectToken(JsonTextReader reader, JsonToken token)
        {
            if (!reader.Read() || reader.TokenType != token)
                throw new JsonException("Expected token: " + token);
        }

        private static void SkipValue(JsonTextReader reader)
        {
            if (reader.TokenType != JsonToken.StartObject &&
                reader.TokenType != JsonToken.StartArray)
            {
                return;
            }

            int depth = reader.Depth;
            while (reader.Read() && reader.Depth > depth)
            {
            }
        }
    }

    internal sealed class DiscordWebhookPublisher
    {
        private readonly string _webhookUrl;

        public DiscordWebhookPublisher(string webhookUrl)
        {
            _webhookUrl = webhookUrl;
        }

        public async Task PublishSingleUpdateGroupAsync(IReadOnlyList<MonitoredBinary> binaries, ParsedWorkerRun parsed, WorkerRunResult workerRun)
        {
            if (string.IsNullOrWhiteSpace(_webhookUrl))
                return;

            var embed = BuildSingleEmbed(binaries, parsed);
            var payload = new JObject
            {
                ["embeds"] = new JArray(embed.ToJson())
            };

            using (var content = new StringContent(payload.ToString(Formatting.None), Encoding.UTF8, "application/json"))
            {
                using (var response = await Program.s_httpClient.PostAsync(_webhookUrl, content).ConfigureAwait(false))
                    response.EnsureSuccessStatusCode();
            }
        }

        public async Task PublishAggregateAsync(IReadOnlyList<MonitoredBinary> binaries, ParsedWorkerRun parsed, WorkerRunResult workerRun)
        {
            if (string.IsNullOrWhiteSpace(_webhookUrl))
                return;

            var embed = BuildAggregateEmbed(binaries, parsed, "New binaries detected");
            var payload = new JObject
            {
                ["embeds"] = new JArray(embed.ToJson())
            };

            using (var content = new StringContent(payload.ToString(Formatting.None), Encoding.UTF8, "application/json"))
            {
                using (var response = await Program.s_httpClient.PostAsync(_webhookUrl, content).ConfigureAwait(false))
                    response.EnsureSuccessStatusCode();
            }
        }

        public async Task PublishFullRunAsync(ParsedWorkerRun parsed, WorkerRunResult workerRun)
        {
            if (string.IsNullOrWhiteSpace(_webhookUrl))
                return;

            var embed = BuildAggregateEmbed(new List<MonitoredBinary>(), parsed, "Patterns updated");
            var content = new MultipartFormDataContent();
            var payload = new JObject { ["embeds"] = new JArray(embed.ToJson()) };
            content.Add(new StringContent(payload.ToString(Formatting.None), Encoding.UTF8, "application/json"), "payload_json");

            if (!string.IsNullOrEmpty(workerRun.HtmlPath) && File.Exists(workerRun.HtmlPath))
            {
                var fileContent = new ByteArrayContent(File.ReadAllBytes(workerRun.HtmlPath));
                fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/html");
                content.Add(fileContent, "files[0]", Path.GetFileName(workerRun.HtmlPath));
            }

            using (var response = await Program.s_httpClient.PostAsync(_webhookUrl, content).ConfigureAwait(false))
                response.EnsureSuccessStatusCode();
        }

        private static DiscordEmbed BuildSingleEmbed(IReadOnlyList<MonitoredBinary> binariesGroup, ParsedWorkerRun parsed)
        {
            var statusLines = new List<StatusLine>();
            Func<ParsedWorkerModuleResult, string, bool> entryFilterAndStatusLineAdder = (parsedModule, ver) =>
            {
                var binary = binariesGroup.FirstOrDefault(b =>
                    string.Equals(b.Candidate.ModuleNameCanonical, parsedModule.ModuleNameCanonical, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(MachineTypes.ToFolderName(b.Candidate.MachineType), parsedModule.Architecture, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(b.RealAssemblyVersion.ToString(), ver, StringComparison.OrdinalIgnoreCase));
                if (binary != null && parsedModule.VersionStatuses.TryGetValue(ver, out int[] statuses))
                {
                    bool withVersion = !(binary.Candidate.AssemblyVersion != null && string.Equals(binary.Candidate.AssemblyVersion.ToString(), ver, StringComparison.OrdinalIgnoreCase));
                    statusLines.Add(new StatusLine
                    {
                        ModuleNameCanonical = binary.Candidate.ModuleNameCanonical,
                        Architecture = MachineTypes.ToFolderName(binary.Candidate.MachineType),
                        Version = ver,
                        Statuses = statuses,
                        SymbolLink = binary.SymbolUrl,
                        WithVersion = withVersion,
                    });
                }
                return binary != null;
            };

            var brokenPatternLines = new List<string>();
            BuildVersionSummaries(
                binariesGroup, parsed, null, brokenPatternLines, out var health, entryFilterAndStatusLineAdder);

            var first = binariesGroup[0];
            string title = BuildTitle(first);
            string description = BuildHeadlineDescription(health, brokenPatternLines, parsed);

            var embed = new DiscordEmbed
            {
                AuthorName = $"New {(binariesGroup.Count == 1 ? "binary" : "binaries")} detected",
                Title = title,
                Url = first.UpdateUrl,
                Description = description,
                Color = HealthColor(health),
                FooterText = parsed.ElapsedTimeSeconds.HasValue ? parsed.ElapsedTimeSeconds.Value.ToString("0.000", CultureInfo.InvariantCulture) + "s" : null,
            };

            foreach (var moduleGroup in statusLines.GroupBy(x => x.ModuleNameCanonical, StringComparer.OrdinalIgnoreCase))
            {
                // int okCount = moduleGroup.SelectMany(x => x.Statuses).Count(x => x == 2);
                // int totalCount = moduleGroup.SelectMany(x => x.Statuses).Count(x => x != 3);

                var sb = new StringBuilder();
                foreach (var line in moduleGroup.OrderBy(x => x.Architecture, StringComparer.OrdinalIgnoreCase))
                {
                    string archText = line.WithVersion ? $"`{TrimTenDotZero(line.Version)} {line.Architecture}`" : $"`{line.Architecture}`";
                    if (!string.IsNullOrWhiteSpace(line.SymbolLink))
                        archText = $"[{archText}]({line.SymbolLink})";
                    sb.Append(archText).Append(' ');
                    foreach (int s in line.Statuses)
                        sb.Append(ToCircleEmoji(s));
                    sb.AppendLine();
                }

                embed.Fields.Add(new DiscordField
                {
                    Name = moduleGroup.Key, // + " (" + okCount.ToString(CultureInfo.InvariantCulture) + "/" + totalCount.ToString(CultureInfo.InvariantCulture) + ")",
                    Value = sb.ToString().TrimEnd(),
                    Inline = false,
                });
            }

            return embed;
        }

        private static DiscordEmbed BuildAggregateEmbed(IReadOnlyList<MonitoredBinary> binaries, ParsedWorkerRun parsed, string author)
        {
            var summaries = new List<ParsedVersionSummary>();
            var brokenPatternLines = new List<string>();
            BuildVersionSummaries(binaries, parsed, summaries, brokenPatternLines, out var health);

            var embed = new DiscordEmbed
            {
                AuthorName = author,
                Title = $"{summaries.Count} {(binaries.Count == 1 ? "binary" : "binaries")} checked",
                Description = BuildHeadlineDescription(health, brokenPatternLines, parsed),
                Color = HealthColor(health),
                FooterText = parsed.ElapsedTimeSeconds.HasValue ? parsed.ElapsedTimeSeconds.Value.ToString("0.000", CultureInfo.InvariantCulture) + "s" : null,
            };

            var versions = summaries
                .Select(x => x.Version)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            embed.Fields.Add(new DiscordField
            {
                Name = "Versions",
                Value = FormatVersionListDescending(versions, 20),
                Inline = false,
            });

            foreach (var moduleGroup in summaries.GroupBy(x => x.ModuleNameCanonical, StringComparer.OrdinalIgnoreCase))
            {
                // twinui.pcshell.dll
                // `amd64` 🟢 10 🟡 2 🔴 2
                // `arm64` 🟢 8 🟡 1 🔴 5

                var sb = new StringBuilder();

                bool has = false;
                foreach (var archGroup in moduleGroup.GroupBy(x => x.Architecture, StringComparer.OrdinalIgnoreCase))
                {
                    if (!has)
                        has = true;
                    else
                        sb.AppendLine();
                    sb.Append('`').Append(archGroup.Key).Append("` ");

                    int okCount = archGroup.SelectMany(x => x.AllStatuses).Count(x => x == 2);
                    int cautionCount = archGroup.SelectMany(x => x.AllStatuses).Count(x => x == 1);
                    int brokenCount = archGroup.SelectMany(x => x.AllStatuses).Count(x => x == 0);

                    bool hasInner = false;
                    if (okCount != 0)
                    {
                        hasInner = true;
                        sb.Append("🟢 ").Append(okCount.ToString(CultureInfo.InvariantCulture));
                    }
                    if (cautionCount != 0)
                    {
                        if (hasInner)
                            sb.Append(' ');
                        hasInner = true;
                        sb.Append("🟡 ").Append(cautionCount.ToString(CultureInfo.InvariantCulture));
                    }
                    if (brokenCount != 0)
                    {
                        if (hasInner)
                            sb.Append(' ');
                        hasInner = true;
                        sb.Append("🔴 ").Append(brokenCount.ToString(CultureInfo.InvariantCulture));
                    }
                }

                embed.Fields.Add(new DiscordField
                {
                    Name = moduleGroup.Key,
                    Value = sb.ToString(),
                    Inline = true,
                });
            }

            return embed;
        }

        private static string BuildTitle(MonitoredBinary binary)
        {
            if (!string.IsNullOrWhiteSpace(binary.UpdateHeading))
                return binary.UpdateHeading;

            if (!string.IsNullOrWhiteSpace(binary.UpdateTitle))
                return binary.UpdateTitle; // + (string.IsNullOrWhiteSpace(binary.InsiderBuild) ? string.Empty : " / " + binary.InsiderBuild);

            if (!string.IsNullOrWhiteSpace(binary.UpdateReleaseVersion))
                return binary.UpdateReleaseVersion;

            return TrimTenDotZero(binary.RealAssemblyVersion.ToString());
        }

        private static string BuildHeadlineDescription(EmbedHealth health, List<string> brokenPatternLines, ParsedWorkerRun parsed)
        {
            string healthStr;
            switch (health)
            {
                case EmbedHealth.Green:
                    healthStr = "✅ All patterns valid";
                    break;
                case EmbedHealth.Yellow:
                    healthStr = "⚠️ Please refine your patterns";
                    break;
                default:
                    healthStr = "🚨 Some patterns need updating";
                    break;
            }

            var sb = new StringBuilder(healthStr);
            for (int i = 0; i < brokenPatternLines.Count && i < 5; i++)
            {
                sb.AppendLine().Append(i + 1).Append(". ").Append(brokenPatternLines[i]);
            }

            return sb.ToString();
        }

        private static void BuildVersionSummaries(
            IReadOnlyList<MonitoredBinary> binaries, ParsedWorkerRun parsed, List<ParsedVersionSummary> summaries,
            List<string> brokenPatternLines, out EmbedHealth health, Func<ParsedWorkerModuleResult, string, bool> entryFilter = null)
        {
            var moduleNames = binaries.Count > 0
                ? binaries.Select(x => x.Candidate.ModuleNameCanonical).Distinct(StringComparer.OrdinalIgnoreCase)
                : parsed.Modules.Select(x => x.ModuleNameCanonical).Distinct(StringComparer.OrdinalIgnoreCase);

            bool hasZero = false;
            bool hasOne = false;
            foreach (var module in parsed.Modules.Where(x => moduleNames.Contains(x.ModuleNameCanonical, StringComparer.OrdinalIgnoreCase)))
            {
                var patternIdxToBrokenVersions = new Dictionary<int, HashSet<string>>();
                foreach (var pair in module.VersionStatuses)
                {
                    if (entryFilter != null && !entryFilter(module, pair.Key))
                        continue;

                    summaries?.Add(new ParsedVersionSummary
                    {
                        ModuleNameCanonical = module.ModuleNameCanonical,
                        Architecture = module.Architecture,
                        Version = pair.Key,
                        AllStatuses = pair.Value,
                        Health = ComputeHealth(pair.Value),
                    });
                    for (int i = 0; i < pair.Value.Length; i++)
                    {
                        int s = pair.Value[i];
                        if (s == 2 || s == 3)
                            continue;
                        if (s == 0)
                            hasZero = true;
                        else if (s == 1)
                            hasOne = true;
                        // This pattern for this module version is broken
                        if (!patternIdxToBrokenVersions.TryGetValue(i, out var brokenVersions))
                        {
                            brokenVersions = new HashSet<string>();
                            patternIdxToBrokenVersions[i] = brokenVersions;
                        }
                        brokenVersions.Add(pair.Key + ' ' + module.Architecture);
                    }
                }
                foreach (var pair in patternIdxToBrokenVersions)
                {
                    int patternIndex = pair.Key;
                    string patternName = parsed.Legends[module.ModuleNameCanonical][patternIndex];
                    string versionsStr = FormatVersionListDescending(pair.Value, 5);
                    brokenPatternLines.Add($"`{patternName}`: {versionsStr}");
                }
            }
            health = hasZero ? EmbedHealth.Red : hasOne ? EmbedHealth.Yellow : EmbedHealth.Green;
        }

        private static EmbedHealth ComputeHealth(IEnumerable<int> statuses)
        {
            bool hasZero = false;
            bool hasOne = false;
            foreach (int status in statuses)
            {
                if (status == 0)
                    hasZero = true;
                else if (status == 1)
                    hasOne = true;
            }

            if (hasZero)
                return EmbedHealth.Red;
            if (hasOne)
                return EmbedHealth.Yellow;
            return EmbedHealth.Green;
        }

        private static int HealthColor(EmbedHealth health)
        {
            switch (health)
            {
                case EmbedHealth.Green:
                    return 0x2ECC71;
                case EmbedHealth.Yellow:
                    return 0xF1C40F;
                default:
                    return 0xE74C3C;
            }
        }

        private static string ToCircleEmoji(int status)
        {
            switch (status)
            {
                case 2:
                    return "🟢";
                case 1:
                    return "🟡";
                default:
                    return "🔴";
            }
        }

        public static string FormatVersionListDescending(IEnumerable<string> versions, int maxExplicit)
        {
            var sorted = versions
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(ParseVersionForSort)
                .Select(TrimTenDotZero)
                .ToList();

            if (sorted.Count == 0)
                return "-";
            if (sorted.Count == 1)
                return sorted[0];
            if (sorted.Count == 2)
                return sorted[0] + " and " + sorted[1];
            if (sorted.Count <= maxExplicit)
                return string.Join(", ", sorted.Take(sorted.Count - 1)) + ", and " + sorted.Last();

            return string.Join(", ", sorted.Take(maxExplicit)) + ", and " + (sorted.Count - maxExplicit).ToString(CultureInfo.InvariantCulture) + " more";
        }

        private static Version ParseVersionForSort(string version)
        {
            if (Version.TryParse(version, out var parsed))
                return parsed;
            return new Version(0, 0);
        }

        private static string TrimTenDotZero(string version)
        {
            return version.StartsWith("10.0.", StringComparison.OrdinalIgnoreCase) ? version.Substring(5) : version;
        }
    }

    internal enum EmbedHealth
    {
        Green,
        Yellow,
        Red,
    }

    internal sealed class StatusLine
    {
        public string ModuleNameCanonical { get; set; }
        public string Architecture { get; set; }
        public string Version { get; set; }
        public int[] Statuses { get; set; }
        public string SymbolLink { get; set; }
        public bool WithVersion { get; set; }
    }

    internal sealed class ParsedVersionSummary
    {
        public string ModuleNameCanonical { get; set; }
        public string Architecture { get; set; }
        public string Version { get; set; }
        public int[] AllStatuses { get; set; }
        public EmbedHealth Health { get; set; }
    }

    internal sealed class DiscordEmbed
    {
        public string AuthorName { get; set; }
        public string Title { get; set; }
        public string Url { get; set; }
        public string Description { get; set; }
        public int Color { get; set; }
        public List<DiscordField> Fields { get; } = new List<DiscordField>();
        public string FooterText { get; set; }

        public JObject ToJson()
        {
            var obj = new JObject
            {
                ["title"] = Title,
                ["description"] = Description,
                ["color"] = Color,
            };
            if (!string.IsNullOrWhiteSpace(Url))
                obj["url"] = Url;
            if (!string.IsNullOrWhiteSpace(AuthorName))
                obj["author"] = new JObject { ["name"] = AuthorName };
            if (Fields.Count > 0)
            {
                obj["fields"] = new JArray(Fields.Select(x => new JObject
                {
                    ["name"] = x.Name,
                    ["value"] = x.Value,
                    ["inline"] = x.Inline,
                }));
            }
            if (!string.IsNullOrWhiteSpace(FooterText))
                obj["footer"] = new JObject { ["text"] = FooterText };
            return obj;
        }
    }

    internal sealed class DiscordField
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public bool Inline { get; set; }
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using static Vanara.PInvoke.VersionDll;

namespace Glue
{
    internal enum WinbindexSource
    {
        X64,
        Arm64,
        Insider
    }

    internal static class Program
    {
        public const string Amd64BaseDataUrl = "https://winbindex.m417z.com/data";
        public const string Arm64BaseDataUrl = "https://m417z.com/winbindex-data-arm64";
        public const string InsiderBaseDataUrl = "https://m417z.com/winbindex-data-insider";

        public const string SymbolServerBaseUrl = "https://msdl.microsoft.com/download/symbols";

        public static readonly HttpClient s_httpClient = CreateHttpClient();

        private static async Task Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            var definitions = new[]
            {
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "explorer.exe",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 15063, 0) },
                    },
                    maxVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 22000, 1) },
                    }
                ),
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "StartTileData.dll",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 22000, 65) },
                        { MachineTypes.ARM64, new Version(10, 0, 22000, 65) },
                    }
                ),
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "twinui.pcshell.dll",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 22000, 65) },
                        { MachineTypes.ARM64, new Version(10, 0, 22000, 65) },
                    }
                ),
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "uxtheme.dll",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 15063, 0) },
                        { MachineTypes.ARM64, new Version(10, 0, 15063, 0) },
                    }
                ),
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "InputSwitch.dll",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 22000, 65) },
                        { MachineTypes.ARM64, new Version(10, 0, 22000, 65) },
                    }
                ),
                new DownloadDefinition(
                    moduleNameWithCanonicalCase: "Windows.UI.Xaml.dll",
                    minVersionsByMachine: new Dictionary<ushort, Version>
                    {
                        { MachineTypes.AMD64, new Version(10, 0, 19041, 1) },
                        { MachineTypes.ARM64, new Version(10, 0, 22000, 65) },
                    }
                ),
            };

            string outputRoot = Path.Combine(Directory.GetCurrentDirectory(), "BinaryCache");
            Directory.CreateDirectory(outputRoot);

            string mode = args.Length == 0 ? "download-all" : args[0].Trim().ToLowerInvariant();
            switch (mode)
            {
                case "normalize-cache":
                    ExistingFileNormalizer.NormalizeExistingFiles(outputRoot, definitions);
                    Console.WriteLine("Normalization complete.");
                    return;

                case "monitor-once":
                    ExistingFileNormalizer.NormalizeExistingFiles(outputRoot, definitions);
                    await ProgramMonitorExtensions.RunMonitorOnceAsync(definitions, outputRoot).ConfigureAwait(false);
                    return;

                case "monitor-loop":
                    ExistingFileNormalizer.NormalizeExistingFiles(outputRoot, definitions);
                    await ProgramMonitorExtensions.RunMonitorLoopAsync(definitions, outputRoot, CancellationToken.None).ConfigureAwait(false);
                    return;

                case "download-all":
                    ExistingFileNormalizer.NormalizeExistingFiles(outputRoot, definitions);
                    await RunDownloadAllAsync(definitions, outputRoot).ConfigureAwait(false);
                    return;

                default:
                    Console.WriteLine("Unknown mode: " + mode);
                    Console.WriteLine("Usage: ep_winbin_test_glue.exe [mode]");
                    Console.WriteLine("Modes:");
                    Console.WriteLine("  normalize-cache   - Normalize existing files in the cache without downloading anything.");
                    Console.WriteLine("  monitor-once      - Check for new versions once and download them.");
                    Console.WriteLine("  monitor-loop      - Continuously check for new versions and download them as they appear.");
                    Console.WriteLine("  download-all      - Download all versions that match the criteria.");
                    return;
            }
        }

        private static async Task RunDownloadAllAsync(IReadOnlyList<DownloadDefinition> definitions, string outputRoot)
        {
            var allCandidates = new List<DownloadCandidate>();

            foreach (var definition in definitions)
            {
                Console.WriteLine("Enumerating " + definition.ModuleNameCanonical + "...");
                var candidates = await WinbindexClient
                    .EnumerateCandidatesFromAllSourcesAsync(definition)
                    .ConfigureAwait(false);

                allCandidates.AddRange(candidates);
                Console.WriteLine("  Found " + candidates.Count + " matching candidates.");
            }

            Console.WriteLine();
            Console.WriteLine("Total candidates: " + allCandidates.Count);

            var deduped = allCandidates
                .GroupBy(
                    x => x.ModuleNameCanonical + "|" +
                         x.MachineType.ToString(CultureInfo.InvariantCulture) + "|" +
                         x.AssemblyVersion + "|" +
                         x.FileHash,
                    StringComparer.OrdinalIgnoreCase)
                .Select(PreferCandidate)
                .ToList();

            Console.WriteLine("After dedupe: " + deduped.Count);

            var downloader = new Downloader(maxParallelism: 8, outputRoot: outputRoot);

            using (var repo = new ManifestRepository(MonitorConstants.ManifestDbPath))
            {
                repo.Initialize();

                var monitoredByKey = new Dictionary<string, MonitoredBinary>(StringComparer.OrdinalIgnoreCase);

                foreach (var candidate in deduped)
                {
                    if (repo.TryInsertDiscoveredBinary(candidate, outputRoot, out var inserted))
                    {
                        monitoredByKey[MakeCandidateKey(candidate)] = inserted;
                    }
                }

                await downloader.DownloadAllAsync(
                    deduped,
                    shouldSkipCandidate: repo.ShouldSkipRetry,
                    onCompleted: (candidate, result) =>
                    {
                        string key = MakeCandidateKey(candidate);

                        if (!monitoredByKey.TryGetValue(key, out var binary))
                        {
                            binary = repo.TryGetBinary(candidate);
                            if (binary == null)
                                return;

                            monitoredByKey[key] = binary;
                        }

                        if (result.Success)
                        {
                            binary.LocalPath = result.FullOutputPath;
                            binary.SymbolUrl = result.UsedUrl;
                            binary.Status = ManifestStatus.Downloaded;
                            binary.DownloadedUtc = DateTime.UtcNow;
                            repo.MarkBinaryDownloaded(binary);
                        }
                        else if (result.ShouldNeverRetry)
                        {
                            repo.MarkBinaryFailedDueToNoWorkingURLs(binary);
                        }
                        else
                        {
                            repo.DeleteBinary(binary);
                        }
                    }).ConfigureAwait(false);
            }

            Console.WriteLine("Done.");
        }

        private static string MakeCandidateKey(DownloadCandidate candidate)
        {
            return candidate.ModuleNameCanonical + "|" +
                   candidate.MachineType.ToString(CultureInfo.InvariantCulture) + "|" +
                   candidate.Source + "|" +
                   candidate.FileHash;
        }

        private static DownloadCandidate PreferCandidate(IEnumerable<DownloadCandidate> group)
        {
            return group
                .OrderBy(x => SourcePriority(x.Source))
                .First();
        }

        private static int SourcePriority(WinbindexSource source)
        {
            switch (source)
            {
                case WinbindexSource.X64:
                case WinbindexSource.Arm64:
                    return 0;
                case WinbindexSource.Insider:
                    return 1;
                default:
                    return 2;
            }
        }

        private static HttpClient CreateHttpClient()
        {
            var client = new HttpClient();
            client.Timeout = TimeSpan.FromMinutes(5);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("WinbindexDownloader/1.0");
            return client;
        }
    }

    internal static class WinbindexClient
    {
        public static async Task<IReadOnlyList<DownloadCandidate>> EnumerateCandidatesFromAllSourcesAsync(DownloadDefinition definition)
        {
            string lowerModuleName = definition.ModuleNameCanonical.ToLowerInvariant();

            var tasks = new[]
            {
                EnumerateCandidatesFromSourceAsync(definition, lowerModuleName, WinbindexSource.X64),
                EnumerateCandidatesFromSourceAsync(definition, lowerModuleName, WinbindexSource.Arm64),
                EnumerateCandidatesFromSourceAsync(definition, lowerModuleName, WinbindexSource.Insider),
            };

            var results = await Task.WhenAll(tasks).ConfigureAwait(false);
            return results.SelectMany(x => x).ToList();
        }

        private sealed class FirstUpdateInfo
        {
            public string Heading { get; set; }
            public string Title { get; set; }
            public string ReleaseDate { get; set; }
            public string ReleaseVersion { get; set; }
            public string UpdateUrl { get; set; }
            public string Build { get; set; }
            public DateTime? CreatedUtc { get; set; }
        }

        private static FirstUpdateInfo GetFirstUpdateInfo(JObject entry, WinbindexSource source)
        {
            if (!(entry["windowsVersions"] is JObject windowsVersions))
                return new FirstUpdateInfo();

            foreach (var windowsVersionProp in windowsVersions.Properties())
            {
                if (!(windowsVersionProp.Value is JObject updates))
                    continue;

                foreach (var updateProp in updates.Properties())
                {
                    if (string.Equals(updateProp.Name, "BASE", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (!(updateProp.Value is JObject updateObj))
                        continue;

                    if (!(updateObj["updateInfo"] is JObject updateInfo))
                        continue;

                    DateTime? createdUtc = null;
                    if (long.TryParse((string)updateInfo["created"] ?? updateInfo["created"]?.ToString(), out var created))
                        createdUtc = DateTimeOffset.FromUnixTimeSeconds(created).UtcDateTime;

                    return new FirstUpdateInfo
                    {
                        Heading = WebUtility.HtmlDecode((string)updateInfo["heading"]),
                        Title = WebUtility.HtmlDecode((string)updateInfo["title"]),
                        ReleaseDate = (string)updateInfo["releaseDate"],
                        ReleaseVersion = (string)updateInfo["releaseVersion"],
                        UpdateUrl = (string)updateInfo["updateUrl"],
                        Build = (string)updateInfo["build"],
                        CreatedUtc = createdUtc,
                    };
                }
            }

            return new FirstUpdateInfo();
        }

        private static async Task<IReadOnlyList<DownloadCandidate>> EnumerateCandidatesFromSourceAsync(
            DownloadDefinition definition,
            string lowerModuleName,
            WinbindexSource source)
        {
            string url = BuildMetadataUrl(source, lowerModuleName);
            var root = await DownloadGzipJsonObjectAsync(url).ConfigureAwait(false);
            var results = new List<DownloadCandidate>();

            foreach (var hashProperty in root.Properties())
            {
                string fileHash = hashProperty.Name;
                if (!(hashProperty.Value is JObject entry))
                    continue;

                if (!(entry["fileInfo"] is JObject fileInfo))
                    continue;

                ushort? machineType = GetMachineType(fileInfo);
                if (!machineType.HasValue)
                    continue;

                if (!SourceAllowsMachineType(source, machineType.Value))
                    continue;

                if (!definition.MinVersionsByMachine.TryGetValue(machineType.Value, out var minVersion))
                    continue;

                definition.MaxVersionsByMachine.TryGetValue(machineType.Value, out var maxVersion);

                // UBR can deviate as time passes but build number should be the same.
                // DO NOT use Winbindex assembly version or SHA256 as key.
                var assemblyVersion = GetAssemblyVersion(entry);
                if (assemblyVersion == null)
                    continue;

                if (assemblyVersion < minVersion)
                    continue;

                if (maxVersion != null && assemblyVersion > maxVersion)
                    continue;

                var urlSet = TryBuildDownloadUrls(lowerModuleName, fileHash, fileInfo);
                if (urlSet == null || urlSet.Candidates.Count == 0)
                    continue;

                /*string archFolder = MachineTypes.ToFolderName(machineType.Value);
                string canonicalBaseName = Path.GetFileNameWithoutExtension(definition.ModuleNameCanonical);
                string extension = Path.GetExtension(definition.ModuleNameCanonical);

                string outputFileName = canonicalBaseName + "_" + assemblyVersion + extension;
                string outputPath = Path.Combine(canonicalBaseName, archFolder, outputFileName);*/

                var firstUpdateInfo = GetFirstUpdateInfo(entry, source);
                results.Add(new DownloadCandidate(
                    source: source,
                    moduleNameCanonical: definition.ModuleNameCanonical,
                    machineType: machineType.Value,
                    assemblyVersion: assemblyVersion,
                    fileHash: fileHash,
                    candidateUrls: urlSet.Candidates,
                    isExactUrl: urlSet.IsExact,
                    updateHeading: firstUpdateInfo.Heading,
                    updateTitle: firstUpdateInfo.Title,
                    updateReleaseDate: firstUpdateInfo.ReleaseDate,
                    updateReleaseVersion: firstUpdateInfo.ReleaseVersion,
                    updateUrl: firstUpdateInfo.UpdateUrl,
                    insiderBuild: firstUpdateInfo.Build,
                    insiderCreatedUtc: firstUpdateInfo.CreatedUtc));
            }

            return results;
        }

        private static bool SourceAllowsMachineType(WinbindexSource source, ushort machineType)
        {
            switch (source)
            {
                case WinbindexSource.X64:
                    return machineType == MachineTypes.AMD64;

                case WinbindexSource.Arm64:
                    return machineType == MachineTypes.ARM64;

                case WinbindexSource.Insider:
                    return machineType == MachineTypes.AMD64 || machineType == MachineTypes.ARM64;

                default:
                    return false;
            }
        }

        private static string BuildMetadataUrl(WinbindexSource source, string lowerModuleName)
        {
            switch (source)
            {
                case WinbindexSource.X64:
                    return Program.Amd64BaseDataUrl + "/by_filename_compressed/" + lowerModuleName + ".json.gz";

                case WinbindexSource.Arm64:
                    return Program.Arm64BaseDataUrl + "/by_filename_compressed/" + lowerModuleName + ".json.gz";

                case WinbindexSource.Insider:
                {
                    uint hash = Djb2Hash(lowerModuleName);
                    string bucket = (hash & 0xFF).ToString("x2", CultureInfo.InvariantCulture);
                    return Program.InsiderBaseDataUrl + "/by_filename_compressed/" + bucket + "/" + lowerModuleName + ".json.gz";
                }

                default:
                    throw new ArgumentOutOfRangeException(nameof(source));
            }
        }

        private static async Task<JObject> DownloadGzipJsonObjectAsync(string url)
        {
            using (var response = await Program.s_httpClient.GetAsync(url).ConfigureAwait(false))
            {
                if (!response.IsSuccessStatusCode)
                    throw new InvalidOperationException("Request failed: HTTP " + (int) response.StatusCode + " for " + url);

                byte[] compressed = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                byte[] jsonBytes = DecompressGzip(compressed);
                string json = Encoding.UTF8.GetString(jsonBytes);
                return JObject.Parse(json);
            }
        }

        private static byte[] DecompressGzip(byte[] compressedBytes)
        {
            using (var input = new MemoryStream(compressedBytes))
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                gzip.CopyTo(output);
                return output.ToArray();
            }
        }

        private static ushort? GetMachineType(JObject fileInfo)
        {
            var token = fileInfo["machineType"];
            if (token == null)
                return null;

            if (token.Type == JTokenType.Integer)
                return (ushort) token.Value<int>();

            if (int.TryParse(token.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
                return (ushort) parsed;

            return null;
        }

        private static Version GetAssemblyVersion(JObject entry)
        {
            var versions = new SortedSet<Version>(Comparer<Version>.Create((a, b) => a.CompareTo(b)));

            if (!(entry["windowsVersions"] is JObject windowsVersions))
                return null;

            foreach (var windowsVersionProp in windowsVersions.Properties())
            {
                if (!(windowsVersionProp.Value is JObject updates))
                    continue;

                foreach (var updateProp in updates.Properties())
                {
                    if (string.Equals(updateProp.Name, "BASE", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (!(updateProp.Value is JObject updateObj))
                        continue;

                    if (!(updateObj["assemblies"] is JObject assemblies))
                        continue;

                    foreach (var assemblyProp in assemblies.Properties())
                    {
                        if (!(assemblyProp.Value is JObject assemblyObj))
                            continue;

                        if (!(assemblyObj["assemblyIdentity"] is JObject assemblyIdentity))
                            continue;

                        string versionText = (string) assemblyIdentity["version"];
                        var parsed = ParseFourPartVersion(versionText);
                        if (parsed != null)
                            versions.Add(parsed);
                    }
                }
            }

            if (versions.Count == 0)
                return null;

            return versions.Min;
        }

        private static Version ParseFourPartVersion(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return null;

            if (Version.TryParse(text, out var parsed))
                return parsed;

            return null;
        }

        private static DownloadUrlSet TryBuildDownloadUrls(string lowerModuleName, string fileHash, JObject fileInfo)
        {
            var timestampToken = fileInfo["timestamp"];
            if (timestampToken == null)
                return null;

            uint timestamp;
            try
            {
                timestamp = Convert.ToUInt32(timestampToken.Value<long>());
            }
            catch
            {
                return null;
            }

            var virtualSizeToken = fileInfo["virtualSize"];
            if (virtualSizeToken != null)
            {
                uint virtualSize = Convert.ToUInt32(virtualSizeToken.Value<long>());
                string url = MakeSymbolServerFileId(lowerModuleName, timestamp, virtualSize);
                return new DownloadUrlSet(new[] { url }, isExact: true);
            }

            var sizeToken = fileInfo["size"];
            var lastSectionPointerToRawDataToken = fileInfo["lastSectionPointerToRawData"];
            var lastSectionVirtualAddressToken = fileInfo["lastSectionVirtualAddress"];

            if (sizeToken != null && lastSectionPointerToRawDataToken != null && lastSectionVirtualAddressToken != null)
            {
                uint size = Convert.ToUInt32(sizeToken.Value<long>());
                uint lastSectionPointerToRawData = Convert.ToUInt32(lastSectionPointerToRawDataToken.Value<long>());
                uint lastSectionVirtualAddress = Convert.ToUInt32(lastSectionVirtualAddressToken.Value<long>());

                var urls = MakeSymbolServerUrlCandidates(
                    lowerModuleName,
                    timestamp,
                    size,
                    lastSectionPointerToRawData,
                    lastSectionVirtualAddress);

                return new DownloadUrlSet(urls, isExact: false);
            }

            return null;
        }

        private static string MakeSymbolServerFileId(string peName, uint timeStamp, uint imageSize)
        {
            return timeStamp.ToString("X8", CultureInfo.InvariantCulture) +
                   imageSize.ToString("X", CultureInfo.InvariantCulture);
        }

        private static List<string> MakeSymbolServerUrlCandidates(
            string peName,
            uint timeStamp,
            uint fileSize,
            uint lastSectionPointerToRawData,
            uint lastSectionVirtualAddress)
        {
            const uint PageSize = 0x1000;

            uint GetMappedSize(uint size)
            {
                uint pageMask = PageSize - 1;
                uint page = size & ~pageMask;
                return page == size ? page : page + PageSize;
            }

            uint lastSectionAndSignatureSize = fileSize - lastSectionPointerToRawData;
            uint lastSectionAndSignatureMappedSize = GetMappedSize(lastSectionVirtualAddress + lastSectionAndSignatureSize);

            uint sizeOfImage = lastSectionAndSignatureMappedSize;
            uint lowestSizeOfImage = lastSectionVirtualAddress + PageSize;

            var urls = new List<string>();
            for (uint size = sizeOfImage; size >= lowestSizeOfImage; size -= PageSize)
            {
                urls.Add(MakeSymbolServerFileId(peName, timeStamp, size));
                if (size == lowestSizeOfImage)
                    break;
            }

            return urls;
        }

        public static string MakeSymbolServerUrl(string peName, string fileId)
        {
            return Program.SymbolServerBaseUrl + "/" + peName + "/" + fileId + "/" + peName;
        }

        private static uint Djb2Hash(string str)
        {
            uint hash = 5381;
            foreach (char c in str)
                hash = ((hash << 5) + hash) + c;
            return hash;
        }
    }

    internal sealed class Downloader
    {
        private readonly int _maxParallelism;
        private readonly string _outputRoot;

        public Downloader(int maxParallelism, string outputRoot)
        {
            _maxParallelism = maxParallelism;
            _outputRoot = outputRoot;
        }

        public async Task DownloadAllAsync(
            IReadOnlyList<DownloadCandidate> candidates,
            Func<DownloadCandidate, bool> shouldSkipCandidate = null,
            Action<DownloadCandidate, DownloadOneResult> onCompleted = null)
        {
            var failures = new ConcurrentBag<string>();

            using (var semaphore = new SemaphoreSlim(_maxParallelism))
            {
                var tasks = candidates.Select(async candidate =>
                {
                    if (shouldSkipCandidate != null && shouldSkipCandidate(candidate))
                    {
                        Console.WriteLine("SKIP   " + candidate.Describe());
                        return;
                    }

                    await semaphore.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        var result = await DownloadOneCoreAsync(candidate).ConfigureAwait(false);
                        onCompleted?.Invoke(candidate, result);
                        if (result.Success)
                        {
                            if (result.WasAlreadyPresent)
                            {
                                Console.WriteLine(
                                    string.Format(
                                        CultureInfo.InvariantCulture,
                                        "EXISTS {0}  [{1}]  {2}",
                                        candidate.Describe(),
                                        candidate.IsExactUrl ? "exact" : "candidate",
                                        result.UsedUrl ?? "-"));
                            }
                            else
                            {
                                Console.WriteLine(
                                    string.Format(
                                        CultureInfo.InvariantCulture,
                                        "OK     {0}  [{1}]  {2}",
                                        candidate.Describe(),
                                        candidate.IsExactUrl ? "exact" : "candidate",
                                        result.UsedUrl ?? "-"));
                            }
                        }
                        else
                        {
                            string reason = result.ShouldNeverRetry
                                ? "No candidate download URL succeeded; suppressing future retries."
                                : "No download URL succeeded.";

                            failures.Add(candidate.Describe() + ": " + reason);
                            Console.WriteLine("FAILED: " + candidate.Describe() + " : " + reason);
                        }
                    }
                    catch (Exception ex)
                    {
                        onCompleted?.Invoke(candidate, null);
                        failures.Add(candidate.Describe() + ": " + ex.Message);
                        Console.WriteLine("FAILED: " + candidate.Describe() + " : " + ex.Message);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }).ToArray();

                await Task.WhenAll(tasks).ConfigureAwait(false);
            }

            if (!failures.IsEmpty)
            {
                Console.WriteLine();
                Console.WriteLine("Failures:");
                foreach (string failure in failures.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                    Console.WriteLine("  " + failure);
            }
        }

        private async Task<DownloadOneResult> DownloadOneCoreAsync(DownloadCandidate candidate)
        {
            var result = new DownloadOneResult();

            string archFolder = MachineTypes.ToFolderName(candidate.MachineType);
            string canonicalBaseName = Path.GetFileNameWithoutExtension(candidate.ModuleNameCanonical);
            string extension = Path.GetExtension(candidate.ModuleNameCanonical);

            string outputDir = Path.Combine(_outputRoot, canonicalBaseName, archFolder);
            Directory.CreateDirectory(outputDir);

            foreach (string fileId in candidate.CandidateUrls)
            {
                string outputFileName = canonicalBaseName + "_" + fileId + extension;
                string fullOutputPath = Path.Combine(outputDir, outputFileName);
                if (File.Exists(fullOutputPath))
                {
                    result.Success = true;
                    result.FullOutputPath = fullOutputPath;
                    result.UsedUrl = WinbindexClient.MakeSymbolServerUrl(candidate.ModuleNameCanonical.ToLowerInvariant(), fileId);
                    result.WasAlreadyPresent = true;
                    return result;
                }
            }

            string tempPath = candidate.FileHash + ".tmp";

            try
            {
                foreach (string fileId in candidate.CandidateUrls)
                {
                    string url = WinbindexClient.MakeSymbolServerUrl(candidate.ModuleNameCanonical.ToLowerInvariant(), fileId);
                    Console.WriteLine("TRY    " + candidate.Describe() + "  [" + (candidate.IsExactUrl ? "exact" : "candidate") + "]  " + url);
                    try
                    {
                        using (var response = await Program.s_httpClient.GetAsync(url).ConfigureAwait(false))
                        {
                            int statusCode = (int) response.StatusCode;

                            if (response.StatusCode == HttpStatusCode.NotFound)
                            {
                                result.Attempts.Add(new DownloadAttemptResult
                                {
                                    Url = url,
                                    Kind = DownloadAttemptKind.NotFound404,
                                    StatusCode = statusCode,
                                });
                                continue;
                            }

                            if (!response.IsSuccessStatusCode)
                            {
                                result.Attempts.Add(new DownloadAttemptResult
                                {
                                    Url = url,
                                    Kind = DownloadAttemptKind.OtherHttpFailure,
                                    StatusCode = statusCode,
                                });
                                continue;
                            }

                            byte[] bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                            if (bytes == null || bytes.Length == 0)
                            {
                                result.Attempts.Add(new DownloadAttemptResult
                                {
                                    Url = url,
                                    Kind = DownloadAttemptKind.TransientFailure,
                                    Error = "Empty response body",
                                });
                                continue;
                            }

                            File.WriteAllBytes(tempPath, bytes);

                            string outputFileName = canonicalBaseName + "_" + fileId + extension;
                            string fullOutputPath = Path.Combine(outputDir, outputFileName);

                            if (File.Exists(fullOutputPath))
                                File.Delete(fullOutputPath);

                            File.Move(tempPath, fullOutputPath);

                            result.Attempts.Add(new DownloadAttemptResult
                            {
                                Url = url,
                                Kind = DownloadAttemptKind.Success,
                                StatusCode = statusCode,
                            });

                            result.Success = true;
                            result.FullOutputPath = fullOutputPath;
                            result.UsedUrl = url;
                            result.WasAlreadyPresent = false;
                            return result;
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        result.Attempts.Add(new DownloadAttemptResult
                        {
                            Url = url,
                            Kind = DownloadAttemptKind.TransientFailure,
                            Error = ex.Message,
                        });
                    }
                    catch (TaskCanceledException ex)
                    {
                        result.Attempts.Add(new DownloadAttemptResult
                        {
                            Url = url,
                            Kind = DownloadAttemptKind.TransientFailure,
                            Error = ex.Message,
                        });
                    }
                    catch (IOException ex)
                    {
                        result.Attempts.Add(new DownloadAttemptResult
                        {
                            Url = url,
                            Kind = DownloadAttemptKind.TransientFailure,
                            Error = ex.Message,
                        });
                    }
                }

                result.Success = false;
                result.ShouldNeverRetry =
                    result.Attempts.Count > 0 &&
                    !candidate.IsExactUrl &&
                    result.Attempts.All(x => x.Kind == DownloadAttemptKind.NotFound404);

                return result;
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }
    }

    internal sealed class DownloadDefinition
    {
        public string ModuleNameCanonical { get; }
        public IReadOnlyDictionary<ushort, Version> MinVersionsByMachine { get; }
        public IReadOnlyDictionary<ushort, Version> MaxVersionsByMachine { get; }

        public DownloadDefinition(
            string moduleNameWithCanonicalCase,
            IDictionary<ushort, Version> minVersionsByMachine,
            IDictionary<ushort, Version> maxVersionsByMachine = null)
        {
            ModuleNameCanonical = moduleNameWithCanonicalCase;
            MinVersionsByMachine = new Dictionary<ushort, Version>(minVersionsByMachine);
            MaxVersionsByMachine = new Dictionary<ushort, Version>(maxVersionsByMachine ?? new Dictionary<ushort, Version>());
        }
    }

    internal sealed class DownloadCandidate
    {
        public WinbindexSource Source { get; }
        public string ModuleNameCanonical { get; }
        public ushort MachineType { get; }
        public Version AssemblyVersion { get; }
        public string FileHash { get; }
        public IReadOnlyList<string> CandidateUrls { get; }
        public bool IsExactUrl { get; }
        public string UpdateHeading { get; }
        public string UpdateTitle { get; }
        public string UpdateReleaseDate { get; }
        public string UpdateReleaseVersion { get; }
        public string UpdateUrl { get; }
        public string InsiderBuild { get; }
        public DateTime? InsiderCreatedUtc { get; }

        public DownloadCandidate(
            WinbindexSource source,
            string moduleNameCanonical,
            ushort machineType,
            Version assemblyVersion,
            string fileHash,
            IReadOnlyList<string> candidateUrls,
            bool isExactUrl,
            string updateHeading = null,
            string updateTitle = null,
            string updateReleaseDate = null,
            string updateReleaseVersion = null,
            string updateUrl = null,
            string insiderBuild = null,
            DateTime? insiderCreatedUtc = null)
        {
            Source = source;
            ModuleNameCanonical = moduleNameCanonical;
            MachineType = machineType;
            AssemblyVersion = assemblyVersion;
            FileHash = fileHash;
            CandidateUrls = candidateUrls;
            IsExactUrl = isExactUrl;
            UpdateHeading = updateHeading;
            UpdateTitle = updateTitle;
            UpdateReleaseDate = updateReleaseDate;
            UpdateReleaseVersion = updateReleaseVersion;
            UpdateUrl = updateUrl;
            InsiderBuild = insiderBuild;
            InsiderCreatedUtc = insiderCreatedUtc;
        }

        public string Describe()
        {
            return string.Format(CultureInfo.InvariantCulture, "{0} {1} ver. {2}", ModuleNameCanonical, MachineTypes.ToFolderName(MachineType), AssemblyVersion);
        }
    }

    internal sealed class DownloadUrlSet
    {
        public IReadOnlyList<string> Candidates { get; }
        public bool IsExact { get; }

        public DownloadUrlSet(IReadOnlyList<string> candidates, bool isExact)
        {
            Candidates = candidates;
            IsExact = isExact;
        }
    }

    internal enum DownloadAttemptKind
    {
        Success,
        NotFound404,
        OtherHttpFailure,
        TransientFailure
    }

    internal sealed class DownloadAttemptResult
    {
        public string Url { get; set; }
        public DownloadAttemptKind Kind { get; set; }
        public int? StatusCode { get; set; }
        public string Error { get; set; }
    }

    internal sealed class DownloadOneResult
    {
        public bool Success { get; set; }
        public bool WasAlreadyPresent { get; set; }
        public bool ShouldNeverRetry { get; set; }
        public string FullOutputPath { get; set; }
        public string UsedUrl { get; set; }
        public List<DownloadAttemptResult> Attempts { get; } = new List<DownloadAttemptResult>();
    }

    internal static class MachineTypes
    {
        public const ushort AMD64 = 0x8664; // 34404
        public const ushort ARM64 = 0xAA64; // 43620

        public static string ToFolderName(ushort machineType)
        {
            switch (machineType)
            {
                case AMD64:
                    return "amd64";
                case ARM64:
                    return "arm64";
                default:
                    return "unknown_" + machineType.ToString(CultureInfo.InvariantCulture);
            }
        }
    }

    internal static class ExistingFileNormalizer
    {
        public static void NormalizeExistingFiles(string binaryCacheRoot, IReadOnlyList<DownloadDefinition> definitions)
        {
            var definitionByLowerOriginalName = definitions.ToDictionary(
                d => d.ModuleNameCanonical.ToLowerInvariant(),
                d => d,
                StringComparer.OrdinalIgnoreCase);

            foreach (string path in Directory.EnumerateFiles(binaryCacheRoot, "*", SearchOption.AllDirectories))
            {
                try
                {
                    NormalizeOneFile(path, definitionByLowerOriginalName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("NORMALIZE FAILED: " + path + " : " + ex.Message);
                }
            }
        }

        private static void NormalizeOneFile(
            string path,
            IReadOnlyDictionary<string, DownloadDefinition> definitionByLowerOriginalName)
        {
            string fileName = Path.GetFileName(path);
            if (LooksNormalized(fileName))
                return;

            if (!TryReadPeIdentity(path, out var info, out string originalFilename, out _))
                return;

            string lowerOriginalFilename = originalFilename.ToLowerInvariant();
            if (!definitionByLowerOriginalName.TryGetValue(lowerOriginalFilename, out var definition))
                return;

            string expectedArchFolder = MachineTypes.ToFolderName(info.MachineType);
            string currentDirectory = Path.GetDirectoryName(path);
            string currentArchFolder = new DirectoryInfo(currentDirectory).Name;
            string moduleDirectory = Directory.GetParent(currentDirectory)?.FullName;

            if (moduleDirectory == null)
            {
                Console.WriteLine("NORMALIZE SKIP (cannot determine module directory): " + path);
                return;
            }

            string targetDirectory = currentDirectory;
            if (!string.Equals(currentArchFolder, expectedArchFolder, StringComparison.OrdinalIgnoreCase))
            {
                targetDirectory = Path.Combine(moduleDirectory, expectedArchFolder);
                Directory.CreateDirectory(targetDirectory);

                Console.WriteLine("NORMALIZE MOVE (arch folder mismatch): " + path + " -> " + targetDirectory);
            }

            string targetFileName = BuildNormalizedFileName(definition, info);
            string targetPath = Path.Combine(targetDirectory, targetFileName);

            if (string.Equals(path, targetPath, StringComparison.OrdinalIgnoreCase))
                return;

            if (File.Exists(targetPath))
            {
                // File.Delete(path);
                // Console.WriteLine("NORMALIZE DELETE (target exists): " + targetPath);
                // return;
                throw new InvalidOperationException("Target path already exists: " + targetPath);
            }

            File.Move(path, targetPath);
            Console.WriteLine("RENAMED " + fileName + " -> " + targetFileName);
        }

        public static string BuildNormalizedFileName(DownloadDefinition definition, PeBasicInfo info)
        {
            string canonicalBaseName = Path.GetFileNameWithoutExtension(definition.ModuleNameCanonical);
            string extension = Path.GetExtension(definition.ModuleNameCanonical);
            return canonicalBaseName + "_" + info.GetSymbolServerKey() + extension;
        }

        private static bool LooksNormalized(string fileName)
        {
            /*string baseName = Path.GetFileNameWithoutExtension(fileName);
            int underscore = baseName.LastIndexOf('_');
            if (underscore <= 0)
                return false;

            string versionPart = baseName.Substring(underscore + 1);
            return Version.TryParse(versionPart, out _);*/
            return false; // needs update for new naming scheme
        }

        private static bool TryReadPeIdentity(string path, out PeBasicInfo info, out string originalFilename, out Version fileVersion)
        {
            originalFilename = null;
            fileVersion = null;
            return PeReader.TryReadBasicInfo(path, out info)
                   && FileVersionReader.TryReadVersionInfo(path, out originalFilename, out fileVersion);
        }
    }

    internal static class FileVersionReader
    {
        public static bool TryReadVersionInfo(string path, out string originalFilename, out Version fileVersion)
        {
            originalFilename = null;
            fileVersion = null;

            uint size = GetFileVersionInfoSize(path, out _);
            if (size == 0)
                return false;

            byte[] buffer = new byte[size];
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                var pBlock = handle.AddrOfPinnedObject();

                if (!GetFileVersionInfo(path, 0, size, pBlock))
                    return false;

                var fixedInfo = QueryStruct<VS_FIXEDFILEINFO>(pBlock, @"\");
                if (fixedInfo.HasValue)
                {
                    var ffi = fixedInfo.Value;
                    int major = HiWord(ffi.dwFileVersionMS);
                    int minor = LoWord(ffi.dwFileVersionMS);
                    int build = HiWord(ffi.dwFileVersionLS);
                    int revision = LoWord(ffi.dwFileVersionLS);
                    fileVersion = new Version(major, minor, build, revision);
                }

                byte[] translationBytes = QueryBytes(pBlock, @"\VarFileInfo\Translation");
                if (translationBytes != null && translationBytes.Length >= 4)
                {
                    ushort lang = BitConverter.ToUInt16(translationBytes, 0);
                    ushort codePage = BitConverter.ToUInt16(translationBytes, 2);

                    string subBlock = string.Format(
                        CultureInfo.InvariantCulture,
                        @"\StringFileInfo\{0:X4}{1:X4}\OriginalFilename",
                        lang,
                        codePage);

                    originalFilename = QueryString(pBlock, subBlock);
                }

                if (string.IsNullOrWhiteSpace(originalFilename))
                {
                    string[] fallbackBlocks =
                    {
                        @"\StringFileInfo\040904B0\OriginalFilename",
                        @"\StringFileInfo\040904E4\OriginalFilename",
                    };

                    foreach (string block in fallbackBlocks)
                    {
                        originalFilename = QueryString(pBlock, block);
                        if (!string.IsNullOrWhiteSpace(originalFilename))
                            break;
                    }
                }

                return fileVersion != null && !string.IsNullOrWhiteSpace(originalFilename);
            }
            finally
            {
                handle.Free();
            }
        }

        private static string QueryString(IntPtr pBlock, string subBlock)
        {
            if (!VerQueryValue(pBlock, subBlock, out var ptr, out _))
                return null;

            if (ptr == IntPtr.Zero)
                return null;

            return Marshal.PtrToStringUni(ptr);
        }

        private static byte[] QueryBytes(IntPtr pBlock, string subBlock)
        {
            if (!VerQueryValue(pBlock, subBlock, out var ptr, out uint len))
                return null;

            if (ptr == IntPtr.Zero || len == 0)
                return null;

            byte[] bytes = new byte[len];
            Marshal.Copy(ptr, bytes, 0, (int) len);
            return bytes;
        }

        private static T? QueryStruct<T>(IntPtr pBlock, string subBlock) where T : struct
        {
            if (!VerQueryValue(pBlock, subBlock, out var ptr, out _))
                return null;

            if (ptr == IntPtr.Zero)
                return null;

            return Marshal.PtrToStructure<T>(ptr);
        }

        private static int HiWord(uint value) => (int) ((value >> 16) & 0xFFFF);
        private static int LoWord(uint value) => (int) (value & 0xFFFF);
    }

    internal sealed class PeBasicInfo
    {
        public ushort MachineType { get; set; }
        public uint TimeDateStamp { get; set; }
        public uint SizeOfImage { get; set; }

        public string GetSymbolServerKey()
        {
            return TimeDateStamp.ToString("X8", CultureInfo.InvariantCulture) +
                   SizeOfImage.ToString("X", CultureInfo.InvariantCulture);
        }
    }

    internal static class PeReader
    {
        public static ushort? TryReadMachineType(string path)
        {
            if (!TryReadBasicInfo(path, out var info))
                return null;

            return info.MachineType;
        }

        public static bool TryReadBasicInfo(string path, out PeBasicInfo info)
        {
            info = null;

            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var br = new BinaryReader(fs))
            {
                if (fs.Length < 0x40)
                    return false;

                fs.Position = 0;
                ushort mz = br.ReadUInt16();
                if (mz != 0x5A4D) // MZ
                    return false;

                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset < 0)
                    return false;

                // Need at least:
                // PE sig (4)
                // IMAGE_FILE_HEADER (20)
                // OptionalHeader.Magic (2)
                if ((long) peOffset + 4 + 20 + 2 > fs.Length)
                    return false;

                fs.Position = peOffset;

                uint peSig = br.ReadUInt32();
                if (peSig != 0x00004550) // PE\0\0
                    return false;

                ushort machine = br.ReadUInt16();
                ushort numberOfSections = br.ReadUInt16();
                uint timeDateStamp = br.ReadUInt32();
                uint pointerToSymbolTable = br.ReadUInt32();
                uint numberOfSymbols = br.ReadUInt32();
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                ushort characteristics = br.ReadUInt16();

                long optionalHeaderStart = fs.Position;
                if (optionalHeaderStart + sizeOfOptionalHeader > fs.Length || sizeOfOptionalHeader < 2)
                    return false;

                ushort magic = br.ReadUInt16();

                uint sizeOfImage;
                switch (magic)
                {
                    case 0x10B: // PE32
                        // IMAGE_OPTIONAL_HEADER32.SizeOfImage is at offset 56 from optional header start.
                        if (sizeOfOptionalHeader < 60)
                            return false;

                        fs.Position = optionalHeaderStart + 56;
                        sizeOfImage = br.ReadUInt32();
                        break;

                    case 0x20B: // PE32+
                        // IMAGE_OPTIONAL_HEADER64.SizeOfImage is also at offset 56 from optional header start.
                        if (sizeOfOptionalHeader < 60)
                            return false;

                        fs.Position = optionalHeaderStart + 56;
                        sizeOfImage = br.ReadUInt32();
                        break;

                    default:
                        return false;
                }

                info = new PeBasicInfo
                {
                    MachineType = machine,
                    TimeDateStamp = timeDateStamp,
                    SizeOfImage = sizeOfImage,
                };

                return true;
            }
        }

        public static string BuildSymbolServerUrl(string pePathOrName, PeBasicInfo info)
        {
            string peName = Path.GetFileName(pePathOrName);
            string key = info.GetSymbolServerKey();
            return Program.SymbolServerBaseUrl + "/" + peName.ToLowerInvariant() + "/" + key + "/" + peName.ToLowerInvariant();
        }
    }
}
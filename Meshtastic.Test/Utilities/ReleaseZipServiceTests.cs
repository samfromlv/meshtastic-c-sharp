using Meshtastic.Cli.Utilities;
using Meshtastic.Protobufs;

namespace Meshtastic.Test.Utilities
{
    [TestFixture]
    public class ReleaseZipServiceTests
    {
        // [Test]
        // public async Task ExtractBinaries_Should_DownloadUf2_ForLatestRakRelease()
        // {
        //     var service = new ReleaseZipService();
        //     var github = new FirmwarePackageService();
        //     var releases = await github.GetFirmwareReleases();
        //     var memoryStream = await github.DownloadRelease(releases.releases.stable.First());
        //     var path = await service.ExtractUpdateBinary(memoryStream, HardwareModel.Rak4631);
        //     path.Should().EndWith(".uf2");
        //     File.Delete(path);
        // }

        [Test]
        [Ignore("This test is ignored because it downloads the latest release from GitHub, which can change over time and cause the test to fail.")]
        public async Task ExtractBinaries_Should_DownloadUpdateBin_ForLatestEsp32Release()
        {
            var service = new ReleaseZipService();
            var github = new FirmwarePackageService();
            var releases = await github.GetFirmwareReleases();
            var memoryStream = await github.DownloadRelease(releases.releases.stable.First());
            var path = await service.ExtractUpdateBinary(memoryStream, HardwareModel.Tbeam);
            path.Should().EndWith("update.bin");
            File.Delete(path);
        }
    }
}

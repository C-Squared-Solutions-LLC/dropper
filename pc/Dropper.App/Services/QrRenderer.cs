using System.Windows.Media;
using System.Windows.Media.Imaging;
using QRCoder;

namespace Dropper.App.Services;

internal static class QrRenderer
{
    /// <summary>One pixel per module (quiet zone included); scale it up with nearest-neighbour sampling.</summary>
    public static BitmapSource Render(string text)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        var matrix = data.ModuleMatrix;
        int n = matrix.Count;
        var pixels = new byte[n * n * 4];
        for (int y = 0; y < n; y++)
        {
            for (int x = 0; x < n; x++)
            {
                byte v = matrix[y][x] ? (byte)0 : (byte)255;
                int i = (y * n + x) * 4;
                pixels[i] = v;
                pixels[i + 1] = v;
                pixels[i + 2] = v;
                pixels[i + 3] = 255;
            }
        }
        var bmp = BitmapSource.Create(n, n, 96, 96, PixelFormats.Bgra32, null, pixels, n * 4);
        bmp.Freeze();
        return bmp;
    }
}

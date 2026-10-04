using System.Net;
using Dropper.Core.Net;
using Dropper.Core.Protocol;
using Dropper.Core.Storage;
using Dropper.Core.Transfer;

namespace Dropper.Tests;

public class SafetyTests
{
    [Theory]
    [InlineData("photo.jpg", "photo.jpg")]
    [InlineData("../../Windows/System32/evil.dll", "evil.dll")]
    [InlineData(@"..\..\evil.exe", "evil.exe")]
    [InlineData("C:\\Users\\x\\a.txt", "a.txt")]
    [InlineData("a<b>c:d\"e|f?g*h.txt", "abcdefgh.txt")]
    [InlineData("CON", "_CON")]
    [InlineData("con.txt", "_con.txt")]
    [InlineData("LPT1.tar.gz", "_LPT1.tar.gz")]
    [InlineData("nul .txt", "_nul .txt")]
    [InlineData("", "file")]
    [InlineData("...", "file")]
    [InlineData("..", "file")]
    [InlineData("   ", "file")]
    [InlineData("trailing. . .", "trailing")]
    [InlineData("invoice\u202Efdp.exe", "invoicefdp.exe")]
    [InlineData("zero\u200Bwidth.txt", "zerowidth.txt")]
    [InlineData("tab\there.txt", "tabhere.txt")]
    [InlineData("shortcut.lnk", "shortcut.lnk.blocked")]
    [InlineData("site.URL", "site.URL.blocked")]
    [InlineData("desktop.scf", "desktop.scf.blocked")]
    [InlineData("emoji 😀.png", "emoji 😀.png")]
    public void Sanitize_file_names(string input, string expected)
    {
        Assert.Equal(expected, FileNames.Sanitize(input));
    }

    [Fact]
    public void Sanitize_caps_length_and_keeps_extension()
    {
        var name = new string('a', 400) + ".jpeg";
        var s = FileNames.Sanitize(name);
        Assert.True(s.Length <= 150);
        Assert.EndsWith(".jpeg", s);
    }

    [Fact]
    public void Sanitize_does_not_split_surrogate_pairs()
    {
        var name = new string('a', 144) + "😀😀😀😀" + ".png";
        var s = FileNames.Sanitize(name);
        Assert.True(s.Length <= 150);
        foreach (var (c, i) in s.Select((c, i) => (c, i)))
            if (char.IsHighSurrogate(c)) Assert.True(i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]));
    }

    [Fact]
    public void MoveToUnique_never_overwrites()
    {
        var dir = Directory.CreateTempSubdirectory("dropper-names").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "original");
            var src = Path.Combine(dir, "incoming.tmp");
            File.WriteAllText(src, "new");
            var final = FileNames.MoveToUnique(src, dir, "a.txt");
            Assert.Equal(Path.Combine(dir, "a (1).txt"), final);
            Assert.Equal("original", File.ReadAllText(Path.Combine(dir, "a.txt")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("Alex's S23 Ultra", "Alex's S23 Ultra")]
    [InlineData("  Phone\u202E\n\tname  ", "Phone name")]
    [InlineData("\u0000\u0007bell", "bell")]
    public void Display_names_are_cleaned(string input, string expected)
    {
        Assert.Equal(expected, TextSafety.CleanDisplayName(input, 64));
    }

    [Theory]
    [InlineData("https://example.com/a?b=c", true)]
    [InlineData("http://example.com", true)]
    [InlineData("  https://example.com  ", true)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("file:///C:/Windows/System32/calc.exe", false)]
    [InlineData("ms-settings:", false)]
    [InlineData("see https://example.com", false)]
    [InlineData("https://", false)]
    [InlineData("", false)]
    public void Link_detection_only_allows_single_web_links(string text, bool expected)
    {
        Assert.Equal(expected, LinkDetector.IsSingleWebLink(text));
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.5.4", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.2.131", true)]
    [InlineData("100.123.196.78", false)] // Tailscale CGNAT range
    [InlineData("8.8.8.8", false)]
    [InlineData("169.254.1.1", false)]
    public void Private_address_detection(string ip, bool expected)
    {
        Assert.Equal(expected, LanInterfaces.IsPrivate(IPAddress.Parse(ip)));
    }

    [Fact]
    public void Subnet_membership()
    {
        var lan = new LanAddress(IPAddress.Parse("192.168.2.131"), 24, "Ethernet", "x");
        Assert.True(lan.Contains(IPAddress.Parse("192.168.2.57")));
        Assert.True(lan.Contains(IPAddress.Parse("::ffff:192.168.2.57")));
        Assert.False(lan.Contains(IPAddress.Parse("192.168.3.57")));
        Assert.False(lan.Contains(IPAddress.Parse("172.25.176.5"))); // WSL vEthernet
        Assert.False(lan.Contains(IPAddress.Parse("100.123.196.1"))); // Tailscale
        Assert.False(lan.Contains(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void Offer_parsing_separates_bad_ids_from_bad_fields()
    {
        string id = new('a', 32);
        var (good, gid) = Messages.ParseOffer(Messages.Offer(new OfferMessage(id, ItemKind.File, "x.txt", "text/plain", 5)));
        Assert.NotNull(good);
        Assert.Equal(id, gid);

        var (bad, bid) = Messages.ParseOffer(System.Text.Encoding.UTF8.GetBytes($"{{\"id\":\"{id}\",\"kind\":\"exe\",\"size\":1}}"));
        Assert.Null(bad);
        Assert.Equal(id, bid);

        var (neg, _) = Messages.ParseOffer(System.Text.Encoding.UTF8.GetBytes($"{{\"id\":\"{id}\",\"kind\":\"file\",\"size\":-5}}"));
        Assert.Null(neg);

        Assert.Throws<ProtocolException>(() => Messages.ParseOffer(System.Text.Encoding.UTF8.GetBytes("{\"id\":\"../../x\",\"kind\":\"file\",\"size\":1}")));
        Assert.Throws<ProtocolException>(() => Messages.ParseOffer(System.Text.Encoding.UTF8.GetBytes("[1,2,3]")));
        Assert.Throws<ProtocolException>(() => Messages.ParseOffer(System.Text.Encoding.UTF8.GetBytes("{not json")));
    }

    [Fact]
    public void Replay_cache_rejects_reuse()
    {
        var cache = new ReplayCache(TimeSpan.FromMinutes(20));
        var nonce = new byte[16];
        nonce[3] = 7;
        var now = DateTimeOffset.UtcNow;
        Assert.True(cache.TryAdd(nonce, now));
        Assert.False(cache.TryAdd(nonce, now.AddMinutes(5)));
        Assert.True(cache.TryAdd(nonce, now.AddMinutes(21)));
    }

    [Fact]
    public void Ip_throttle_blocks_after_ten_failures()
    {
        var t = new IpThrottle(10, TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(5));
        var ip = IPAddress.Parse("192.168.2.50");
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < 9; i++) Assert.False(t.Record(ip, now.AddSeconds(i)));
        Assert.True(t.Record(ip, now.AddSeconds(9)));
        Assert.True(t.IsBlocked(ip, now.AddMinutes(4)));
        Assert.False(t.IsBlocked(ip, now.AddMinutes(6)));
        Assert.False(t.IsBlocked(IPAddress.Parse("192.168.2.51"), now));
    }
}

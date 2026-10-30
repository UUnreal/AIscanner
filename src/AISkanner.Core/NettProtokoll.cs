using System.Net;

namespace AISkanner;

/// <summary>
/// Hva en port og en adresse betyr i Nettverk: QUIC, WebRTC, DNS, kryptert DNS og lokale AI-servere.
/// Bare tolkning av tall Windows allerede har gitt; ingenting kobles til.
/// </summary>
public static class NettProtokoll
{
    /// <summary>Hva UDP-trafikk mot en fjern port vanligvis er.</summary>
    public static string Udp(int port) => port switch
    {
        443 => "QUIC (HTTP/3)",
        3478 or 5349 or (>= 19302 and <= 19309) => "STUN/TURN (WebRTC)",
        53 => "DNS",
        853 => "DNS over QUIC",
        4791 => "RoCEv2 (RDMA)",
        123 => "tid (NTP)",
        >= 1024 => "høy port (f.eks. WebRTC-lyd/-video)",
        _ => $"port {port}",
    };

    /// <summary>Kjente offentlige DNS-servere. TCP 443 mot dem er DNS over HTTPS, TCP 853 DNS over TLS.</summary>
    private static readonly Dictionary<string, string> DnsTjenester = new()
    {
        ["1.1.1.1"] = "Cloudflare", ["1.0.0.1"] = "Cloudflare", ["2606:4700:4700::1111"] = "Cloudflare", ["2606:4700:4700::1001"] = "Cloudflare",
        ["8.8.8.8"] = "Google", ["8.8.4.4"] = "Google", ["2001:4860:4860::8888"] = "Google", ["2001:4860:4860::8844"] = "Google",
        ["9.9.9.9"] = "Quad9", ["149.112.112.112"] = "Quad9", ["2620:fe::fe"] = "Quad9", ["2620:fe::9"] = "Quad9",
        ["208.67.222.222"] = "OpenDNS", ["208.67.220.220"] = "OpenDNS",
        ["94.140.14.14"] = "AdGuard", ["94.140.15.15"] = "AdGuard",
        ["194.242.2.2"] = "Mullvad", ["45.90.28.0"] = "NextDNS", ["45.90.30.0"] = "NextDNS",
    };

    /// <summary>«DNS over HTTPS (Cloudflare)» for TCP 443 mot en kjent DNS-server, «DNS over TLS» for 853, ellers null.</summary>
    public static string? KryptertDns(IPAddress ip, int port, bool tcp)
    {
        var tjeneste = DnsTjenester.TryGetValue(ip.ToString(), out var t) ? t : null;
        if (port == 853) return tcp ? $"DNS over TLS{(tjeneste != null ? $" ({tjeneste})" : "")}" : $"DNS over QUIC{(tjeneste != null ? $" ({tjeneste})" : "")}";
        if (port == 443 && tjeneste != null) return tcp ? $"DNS over HTTPS ({tjeneste})" : $"DNS over HTTPS/3 ({tjeneste})";
        return null;
    }

    /// <summary>Porter AI-servere lytter på som standard. Spesifikke = brukes nesten bare av AI.</summary>
    public static readonly Dictionary<int, (string Hva, bool Spesifikk)> AiPorter = new()
    {
        [11434] = ("Ollama", true), [1234] = ("LM Studio", true), [7860] = ("Gradio / Text Generation WebUI", true),
        [29500] = ("PyTorch distribuert trening (NCCL)", true), [8500] = ("TensorFlow Serving (gRPC)", true), [8501] = ("TensorFlow Serving (REST)", true),
        [8001] = ("NVIDIA Triton (gRPC)", true), [8002] = ("NVIDIA Triton (metrikker)", true), [4891] = ("GPT4All", true), [1337] = ("Jan", true),
        [8000] = ("vLLM / NVIDIA Triton (HTTP)", false), [8080] = ("llama.cpp server / Open WebUI", false), [5000] = ("Text Generation WebUI (API)", false),
        [3000] = ("Open WebUI", false), [8888] = ("Jupyter", false),
    };

    /// <summary>Lytter på alle nettverkskort (0.0.0.0 eller ::) eller en adresse som ikke er PC-en selv: kan nås fra andre maskiner.</summary>
    public static bool Apen(IPAddress a) => !IPAddress.IsLoopback(a);

    /// <summary>
    /// Om en lyttende port skal vises som AI-server: porter som nesten bare brukes av AI, eller vanlige porter
    /// når programmet er et kjent AI-program eller en tolker (python, node …). Ellers er det vanlig webserver-støy.
    /// </summary>
    public static bool VisLytter(int port, bool udp, string program, bool aiProgram)
    {
        if (udp) return port == 4791;
        if (!AiPorter.TryGetValue(port, out var p)) return aiProgram;
        return p.Spesifikk || aiProgram || Kommandolinje.Tolkere.Contains(program);
    }
}

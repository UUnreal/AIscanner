using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace AISkanner;

/// <summary>Denne PC-ens egen adresse på nettet: IP og MAC på kortet som har standard gateway. Lest fra Windows nå.</summary>
public static class Enhet
{
    public static string? Tekst()
    {
        try
        {
            var kort = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .OrderByDescending(n => n.GetIPProperties().GatewayAddresses.Any(g => !g.Address.Equals(System.Net.IPAddress.Any)))
                .FirstOrDefault();
            if (kort == null) return null;
            var ip = kort.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
            var mac = string.Join("-", kort.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
            return $"IP {ip?.ToString() ?? "ingen"}{(mac.Length > 0 ? $" · MAC {mac}" : "")} ({kort.Name})";
        }
        catch { return null; }
    }
}

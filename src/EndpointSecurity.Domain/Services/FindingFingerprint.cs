using System.Security.Cryptography;
using System.Text;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Domain.Services;

public static class FindingFingerprint
{
    public static string Create(SecurityFinding finding)
    {
        return Create(
            finding.Category,
            finding.Title,
            finding.ProcessName,
            finding.FilePath);
    }

    public static string Create(
        FindingCategory category,
        string title,
        string? processName,
        string? filePath)
    {
        var normalizedPath = filePath?
            .Trim()
            .Replace('/', '\\')
            .ToUpperInvariant();

        var material = string.Join(
            "|",
            category.ToString().ToUpperInvariant(),
            title.Trim().ToUpperInvariant(),
            processName?.Trim().ToUpperInvariant() ??
                string.Empty,
            normalizedPath ?? string.Empty);

        var hash = SHA256.HashData(
            Encoding.UTF8.GetBytes(material));

        return Convert.ToHexString(hash);
    }
}

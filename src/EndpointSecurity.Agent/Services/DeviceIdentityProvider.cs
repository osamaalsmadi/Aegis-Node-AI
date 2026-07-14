namespace EndpointSecurity.Agent.Services;

public sealed class DeviceIdentityProvider
{
    private Guid? _cachedDeviceId;

    public Guid GetOrCreateDeviceId()
    {
        if (_cachedDeviceId.HasValue)
        {
            return _cachedDeviceId.Value;
        }

        var commonDataPath = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "EndpointSecurity",
            "device-id.txt");

        try
        {
            _cachedDeviceId = GetOrCreateAtPath(commonDataPath);
        }
        catch (UnauthorizedAccessException)
        {
            var localDataPath = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "EndpointSecurity",
                "device-id.txt");

            _cachedDeviceId = GetOrCreateAtPath(localDataPath);
        }

        return _cachedDeviceId.Value;
    }

    private static Guid GetOrCreateAtPath(string filePath)
    {
        if (File.Exists(filePath))
        {
            var savedValue = File.ReadAllText(filePath).Trim();

            if (Guid.TryParse(savedValue, out var savedDeviceId))
            {
                return savedDeviceId;
            }
        }

        var deviceId = Guid.NewGuid();
        var directory = Path.GetDirectoryName(filePath)
            ?? throw new InvalidOperationException(
                "Device identity directory was not found.");

        Directory.CreateDirectory(directory);
        File.WriteAllText(filePath, deviceId.ToString());

        return deviceId;
    }
}

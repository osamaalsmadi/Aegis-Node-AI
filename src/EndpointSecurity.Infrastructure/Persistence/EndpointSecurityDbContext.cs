using EndpointSecurity.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Persistence;

public sealed class EndpointSecurityDbContext(
    DbContextOptions<EndpointSecurityDbContext> options)
    : DbContext(options)
{
    public DbSet<ManagedDevice> ManagedDevices =>
        Set<ManagedDevice>();

    public DbSet<SecurityPostureSnapshot> SecurityPostureSnapshots =>
        Set<SecurityPostureSnapshot>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        var device = modelBuilder.Entity<ManagedDevice>();

        device.ToTable("ManagedDevices");
        device.HasKey(x => x.Id);

        device.Property(x => x.HostName)
            .HasMaxLength(255)
            .IsRequired();

        device.Property(x => x.OperatingSystem)
            .HasMaxLength(100)
            .IsRequired();

        device.Property(x => x.OperatingSystemVersion)
            .HasMaxLength(100)
            .IsRequired();

        device.Property(x => x.Architecture)
            .HasMaxLength(30)
            .IsRequired();

        device.Property(x => x.AgentVersion)
            .HasMaxLength(30)
            .IsRequired();

        device.Property(x => x.Status)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        device.Property(x => x.RiskScore)
            .IsRequired();

        device.HasIndex(x => x.HostName);
        device.HasIndex(x => x.LastSeenUtc);

        var snapshot =
            modelBuilder.Entity<SecurityPostureSnapshot>();

        snapshot.ToTable("SecurityPostureSnapshots");
        snapshot.HasKey(x => x.Id);

        snapshot.Property(x => x.RiskScore)
            .IsRequired();

        snapshot.Property(x => x.CollectedAtUtc)
            .IsRequired();

        snapshot.HasOne<ManagedDevice>()
            .WithMany()
            .HasForeignKey(x => x.DeviceId)
            .OnDelete(DeleteBehavior.Cascade);

        snapshot.HasIndex(x => new
        {
            x.DeviceId,
            x.CollectedAtUtc
        });
    }
}

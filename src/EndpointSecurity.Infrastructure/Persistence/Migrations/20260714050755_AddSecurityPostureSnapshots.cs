using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddSecurityPostureSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecurityPostureSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DefenderEnabled = table.Column<bool>(type: "bit", nullable: true),
                    RealTimeProtectionEnabled = table.Column<bool>(type: "bit", nullable: true),
                    AntivirusSignatureAgeDays = table.Column<int>(type: "int", nullable: true),
                    FirewallDomainEnabled = table.Column<bool>(type: "bit", nullable: true),
                    FirewallPrivateEnabled = table.Column<bool>(type: "bit", nullable: true),
                    FirewallPublicEnabled = table.Column<bool>(type: "bit", nullable: true),
                    RebootRequired = table.Column<bool>(type: "bit", nullable: true),
                    RiskScore = table.Column<int>(type: "int", nullable: false),
                    CollectedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityPostureSnapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityPostureSnapshots_ManagedDevices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "ManagedDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityPostureSnapshots_DeviceId_CollectedAtUtc",
                table: "SecurityPostureSnapshots",
                columns: new[] { "DeviceId", "CollectedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityPostureSnapshots");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddEndpointTelemetry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EndpointTelemetryScans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProcessCount = table.Column<int>(type: "int", nullable: false),
                    ActiveTcpConnectionCount = table.Column<int>(type: "int", nullable: false),
                    RiskScore = table.Column<int>(type: "int", nullable: false),
                    CollectedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EndpointTelemetryScans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EndpointTelemetryScans_ManagedDevices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "ManagedDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecurityFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScanId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    Title = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false),
                    ProcessName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    ProcessId = table.Column<int>(type: "int", nullable: true),
                    FilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    CommandLine = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    DetectedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityFindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityFindings_EndpointTelemetryScans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "EndpointTelemetryScans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EndpointTelemetryScans_DeviceId_CollectedAtUtc",
                table: "EndpointTelemetryScans",
                columns: new[] { "DeviceId", "CollectedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityFindings_DetectedAtUtc",
                table: "SecurityFindings",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityFindings_DeviceId",
                table: "SecurityFindings",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityFindings_ScanId",
                table: "SecurityFindings",
                column: "ScanId");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityFindings_Severity",
                table: "SecurityFindings",
                column: "Severity");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecurityFindings");

            migrationBuilder.DropTable(
                name: "EndpointTelemetryScans");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddNetworkConnectionDetails : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SecurityFindings_DetectedAtUtc",
                table: "SecurityFindings");

            migrationBuilder.CreateTable(
                name: "NetworkConnectionSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScanId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Protocol = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: false),
                    LocalAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    LocalPort = table.Column<int>(type: "int", nullable: false),
                    RemoteAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RemotePort = table.Column<int>(type: "int", nullable: false),
                    State = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    ProcessId = table.Column<int>(type: "int", nullable: false),
                    ProcessName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    CollectedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkConnectionSnapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_NetworkConnectionSnapshots_EndpointTelemetryScans_ScanId",
                        column: x => x.ScanId,
                        principalTable: "EndpointTelemetryScans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkConnectionSnapshots_DeviceId",
                table: "NetworkConnectionSnapshots",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkConnectionSnapshots_RemoteAddress",
                table: "NetworkConnectionSnapshots",
                column: "RemoteAddress");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkConnectionSnapshots_RemotePort",
                table: "NetworkConnectionSnapshots",
                column: "RemotePort");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkConnectionSnapshots_ScanId",
                table: "NetworkConnectionSnapshots",
                column: "ScanId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkConnectionSnapshots");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityFindings_DetectedAtUtc",
                table: "SecurityFindings",
                column: "DetectedAtUtc");
        }
    }
}

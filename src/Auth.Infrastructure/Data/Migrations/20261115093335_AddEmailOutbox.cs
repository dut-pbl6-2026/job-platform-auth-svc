using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEmailOutbox : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EmailOutboxMessages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Recipient = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Link = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    LinkExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    LastError = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    LockedUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LockToken = table.Column<Guid>(type: "uuid", nullable: true),
                    SentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    GaveUpAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailOutboxMessages", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EmailOutboxMessages_Pending",
                table: "EmailOutboxMessages",
                column: "NextAttemptAt",
                filter: "\"SentAt\" IS NULL AND \"GaveUpAt\" IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EmailOutboxMessages");
        }
    }
}

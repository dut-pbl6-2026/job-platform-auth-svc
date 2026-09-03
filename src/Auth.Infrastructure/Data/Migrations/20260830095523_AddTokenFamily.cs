using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTokenFamily : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;");

            migrationBuilder.AddColumn<Guid>(
                name: "TokenFamily",
                table: "RefreshTokens",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.Sql("UPDATE \"RefreshTokens\" SET \"TokenFamily\" = gen_random_uuid() WHERE \"TokenFamily\" = '00000000-0000-0000-0000-000000000000'");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_TokenFamily",
                table: "RefreshTokens",
                column: "TokenFamily");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserId_TokenFamily",
                table: "RefreshTokens",
                columns: new[] { "UserId", "TokenFamily" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_TokenFamily",
                table: "RefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_UserId_TokenFamily",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "TokenFamily",
                table: "RefreshTokens");
        }
    }
}

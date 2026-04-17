using Widiny.Stock.Web.Data;
using Widiny.Stock.Web.Models.Auth;
using Widiny.Stock.Web.Models.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Widiny.Stock.Web.Services.Auth;

public class AdminAccountService(
    StockDbContext dbContext,
    IOptions<AdminAuthOptions> options)
{
    public async Task EnsureSeedAdminAsync()
    {
        if (await dbContext.Admins.AnyAsync())
        {
            return;
        }

        var config = options.Value;
        var loginId = string.IsNullOrWhiteSpace(config.LoginId) ? config.PrimaryEmail : config.LoginId;
        var primaryEmail = string.IsNullOrWhiteSpace(config.PrimaryEmail) ? loginId : config.PrimaryEmail;

        var admin = new AdminEntity
        {
            LoginId = loginId,
            FirstName = config.FirstName,
            LastName = config.LastName,
            PrimaryEmail = primaryEmail,
            TotpSecretBase32 = string.IsNullOrWhiteSpace(config.TotpSecretBase32)
                ? TotpUtility.GenerateSecret()
                : config.TotpSecretBase32,
            CreateDate = DateTime.UtcNow,
            ModifyDate = DateTime.UtcNow
        };

        SetPassword(admin, config.Password);
        dbContext.Admins.Add(admin);
        await dbContext.SaveChangesAsync();
    }

    public async Task<bool> TryRegisterAsync(AdminRegisterViewModel model)
    {
        var exists = await dbContext.Admins.AnyAsync(x => x.LoginId == model.LoginId);
        if (exists)
        {
            return false;
        }

        var admin = new AdminEntity
        {
            LoginId = model.LoginId,
            FirstName = model.FirstName,
            LastName = model.LastName,
            PrimaryEmail = model.PrimaryEmail,
            TotpSecretBase32 = TotpUtility.GenerateSecret(),
            CreateDate = DateTime.UtcNow,
            ModifyDate = DateTime.UtcNow
        };

        SetPassword(admin, model.Password);

        dbContext.Admins.Add(admin);
        await dbContext.SaveChangesAsync();

        return true;
    }

    public async Task<bool> VerifyCredentialsAsync(string loginId, string password)
    {
        var admin = await dbContext.Admins.AsNoTracking().SingleOrDefaultAsync(x => x.LoginId == loginId);
        if (admin is null)
        {
            return false;
        }

        return VerifyPassword(password, admin.PasswordHash, admin.PasswordSalt);
    }

    public async Task<string?> GetTotpSecretByLoginIdAsync(string loginId)
    {
        return await dbContext.Admins
            .Where(x => x.LoginId == loginId)
            .Select(x => x.TotpSecretBase32)
            .SingleOrDefaultAsync();
    }

    public async Task<string?> GetAuthenticatorSetupKeyAsync(string loginId)
    {
        return await GetTotpSecretByLoginIdAsync(loginId);
    }

    public async Task<string> GetDisplayNameAsync(string loginId)
    {
        var admin = await dbContext.Admins
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.LoginId == loginId);

        if (admin is null)
        {
            return loginId;
        }

        return $"{admin.FirstName} {admin.LastName}".Trim();
    }

    private static void SetPassword(AdminEntity admin, string password)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 100_000, HashAlgorithmName.SHA256, 32);

        admin.PasswordSalt = Convert.ToBase64String(saltBytes);
        admin.PasswordHash = Convert.ToBase64String(hashBytes);
    }

    private static bool VerifyPassword(string password, string encodedHash, string encodedSalt)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(encodedHash) || string.IsNullOrWhiteSpace(encodedSalt))
        {
            return false;
        }

        var saltBytes = Convert.FromBase64String(encodedSalt);
        var expectedHash = Convert.FromBase64String(encodedHash);
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 100_000, HashAlgorithmName.SHA256, 32);

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}

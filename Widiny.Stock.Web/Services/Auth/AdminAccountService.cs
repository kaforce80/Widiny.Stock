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
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

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
            TwoFactorEnabled = true,
            CreateDate = DateTime.UtcNow,
            ModifyDate = DateTime.UtcNow
        };

        SetPassword(admin, config.Password);
        dbContext.Admins.Add(admin);
        await dbContext.SaveChangesAsync();
        await GenerateRecoveryCodesInternalAsync(admin.Id, 10);
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
            TwoFactorEnabled = true,
            FailedLoginAttempts = 0,
            LockoutEndUtc = null,
            CreateDate = DateTime.UtcNow,
            ModifyDate = DateTime.UtcNow
        };

        SetPassword(admin, model.Password);
        dbContext.Admins.Add(admin);
        await dbContext.SaveChangesAsync();
        await GenerateRecoveryCodesInternalAsync(admin.Id, 10);

        return true;
    }

    public async Task<PasswordVerificationResult> VerifyCredentialsAsync(string loginId, string password, string? ipAddress = null)
    {
        var admin = await dbContext.Admins.SingleOrDefaultAsync(x => x.LoginId == loginId);
        if (admin is null)
        {
            await AddAuditLogAsync(loginId, "LOGIN_PASSWORD", false, "Unknown login id", ipAddress);
            return new PasswordVerificationResult();
        }

        if (IsLockedOut(admin))
        {
            await AddAuditLogAsync(loginId, "LOGIN_PASSWORD", false, "Account locked out", ipAddress);
            return new PasswordVerificationResult
            {
                IsLockedOut = true,
                LockoutEndUtc = admin.LockoutEndUtc
            };
        }

        var passwordValid = VerifyPassword(password, admin.PasswordHash, admin.PasswordSalt);
        if (!passwordValid)
        {
            await RegisterFailedAttemptAsync(admin, "LOGIN_PASSWORD", ipAddress);
            return new PasswordVerificationResult();
        }

        admin.FailedLoginAttempts = 0;
        admin.LockoutEndUtc = null;
        admin.ModifyDate = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();

        if (!admin.TwoFactorEnabled || string.IsNullOrWhiteSpace(admin.TotpSecretBase32))
        {
            await AddAuditLogAsync(loginId, "LOGIN_PASSWORD", false, "2FA not configured", ipAddress);
            return new PasswordVerificationResult
            {
                RequiresTwoFactorSetup = true
            };
        }

        await AddAuditLogAsync(loginId, "LOGIN_PASSWORD", true, "Password verified", ipAddress);
        return new PasswordVerificationResult
        {
            IsSuccess = true
        };
    }

    public async Task<TwoFactorVerificationResult> VerifyTwoFactorOrRecoveryAsync(string loginId, string codeOrRecovery, string? ipAddress = null)
    {
        var admin = await dbContext.Admins.SingleOrDefaultAsync(x => x.LoginId == loginId);
        if (admin is null)
        {
            await AddAuditLogAsync(loginId, "LOGIN_2FA", false, "Unknown login id", ipAddress);
            return new TwoFactorVerificationResult();
        }

        if (IsLockedOut(admin))
        {
            await AddAuditLogAsync(loginId, "LOGIN_2FA", false, "Account locked out", ipAddress);
            return new TwoFactorVerificationResult
            {
                IsLockedOut = true,
                LockoutEndUtc = admin.LockoutEndUtc
            };
        }

        var normalizedInput = codeOrRecovery.Trim().Replace("-", string.Empty);
        var isTotp = normalizedInput.Length == 6 && normalizedInput.All(char.IsDigit);

        if (isTotp)
        {
            var isTotpValid = TotpUtility.VerifyCode(admin.TotpSecretBase32, normalizedInput);
            if (isTotpValid)
            {
                admin.FailedLoginAttempts = 0;
                admin.LockoutEndUtc = null;
                admin.ModifyDate = DateTime.UtcNow;
                await dbContext.SaveChangesAsync();
                await AddAuditLogAsync(loginId, "LOGIN_2FA", true, "TOTP code verified", ipAddress);

                return new TwoFactorVerificationResult
                {
                    IsSuccess = true,
                    UsedRecoveryCode = false
                };
            }
        }
        else
        {
            var recoveryCodes = await dbContext.AdminRecoveryCodes
                .Where(x => x.AdminId == admin.Id && x.UsedDateUtc == null)
                .ToListAsync();

            foreach (var recoveryCode in recoveryCodes)
            {
                if (!VerifyPassword(normalizedInput, recoveryCode.CodeHash, recoveryCode.CodeSalt))
                {
                    continue;
                }

                recoveryCode.UsedDateUtc = DateTime.UtcNow;
                recoveryCode.ModifyDate = DateTime.UtcNow;
                admin.FailedLoginAttempts = 0;
                admin.LockoutEndUtc = null;
                admin.ModifyDate = DateTime.UtcNow;
                await dbContext.SaveChangesAsync();

                await AddAuditLogAsync(loginId, "LOGIN_2FA", true, "Recovery code used", ipAddress);
                return new TwoFactorVerificationResult
                {
                    IsSuccess = true,
                    UsedRecoveryCode = true
                };
            }
        }

        await RegisterFailedAttemptAsync(admin, "LOGIN_2FA", ipAddress);
        return new TwoFactorVerificationResult();
    }

    public async Task<bool> ConfirmPasswordAsync(string loginId, string password)
    {
        var admin = await dbContext.Admins.AsNoTracking().SingleOrDefaultAsync(x => x.LoginId == loginId);
        if (admin is null)
        {
            return false;
        }

        return VerifyPassword(password, admin.PasswordHash, admin.PasswordSalt);
    }

    public async Task<List<string>> DisableTwoFactorAsync(string loginId)
    {
        var admin = await dbContext.Admins.SingleAsync(x => x.LoginId == loginId);
        admin.TwoFactorEnabled = false;
        admin.ModifyDate = DateTime.UtcNow;

        var recoveryCodes = await dbContext.AdminRecoveryCodes.Where(x => x.AdminId == admin.Id).ToListAsync();
        dbContext.AdminRecoveryCodes.RemoveRange(recoveryCodes);

        await dbContext.SaveChangesAsync();
        await AddAuditLogAsync(loginId, "2FA_DISABLE", true, "2FA disabled by admin", null);

        return [];
    }

    public async Task<(string Secret, List<string> RecoveryCodes)> ResetTwoFactorAsync(string loginId)
    {
        var admin = await dbContext.Admins.SingleAsync(x => x.LoginId == loginId);
        admin.TotpSecretBase32 = TotpUtility.GenerateSecret();
        admin.TwoFactorEnabled = true;
        admin.ModifyDate = DateTime.UtcNow;

        var existingRecoveryCodes = await dbContext.AdminRecoveryCodes.Where(x => x.AdminId == admin.Id).ToListAsync();
        dbContext.AdminRecoveryCodes.RemoveRange(existingRecoveryCodes);

        await dbContext.SaveChangesAsync();

        var plainCodes = await GenerateRecoveryCodesInternalAsync(admin.Id, 10);
        await AddAuditLogAsync(loginId, "2FA_RESET", true, "2FA secret reset", null);

        return (admin.TotpSecretBase32, plainCodes);
    }

    public async Task<bool> ChangePasswordAsync(string loginId, string currentPassword, string newPassword)
    {
        var admin = await dbContext.Admins.SingleOrDefaultAsync(x => x.LoginId == loginId);
        if (admin is null || !VerifyPassword(currentPassword, admin.PasswordHash, admin.PasswordSalt))
        {
            await AddAuditLogAsync(loginId, "PASSWORD_CHANGE", false, "Current password mismatch", null);
            return false;
        }

        SetPassword(admin, newPassword);
        admin.ModifyDate = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();
        await AddAuditLogAsync(loginId, "PASSWORD_CHANGE", true, "Password changed", null);
        return true;
    }

    public async Task<List<string>> GenerateNewRecoveryCodesAsync(string loginId)
    {
        var admin = await dbContext.Admins.SingleAsync(x => x.LoginId == loginId);
        var existingRecoveryCodes = await dbContext.AdminRecoveryCodes.Where(x => x.AdminId == admin.Id).ToListAsync();
        dbContext.AdminRecoveryCodes.RemoveRange(existingRecoveryCodes);
        await dbContext.SaveChangesAsync();

        var codes = await GenerateRecoveryCodesInternalAsync(admin.Id, 10);
        await AddAuditLogAsync(loginId, "2FA_RECOVERY_REGENERATE", true, "Recovery codes regenerated", null);
        return codes;
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

    public async Task<bool> IsTwoFactorEnabledAsync(string loginId)
    {
        return await dbContext.Admins.Where(x => x.LoginId == loginId).Select(x => x.TwoFactorEnabled).SingleOrDefaultAsync();
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

    public async Task AddAuditLogAsync(string? loginId, string eventType, bool isSuccess, string? detail, string? ipAddress)
    {
        dbContext.AuthAuditLogs.Add(new AuthAuditLogEntity
        {
            LoginId = loginId,
            EventType = eventType,
            IsSuccess = isSuccess,
            Detail = detail,
            IpAddress = ipAddress,
            CreateDate = DateTime.UtcNow,
            ModifyDate = DateTime.UtcNow
        });

        await dbContext.SaveChangesAsync();
    }

    private static bool IsLockedOut(AdminEntity admin) => admin.LockoutEndUtc.HasValue && admin.LockoutEndUtc.Value > DateTime.UtcNow;

    private async Task RegisterFailedAttemptAsync(AdminEntity admin, string eventType, string? ipAddress)
    {
        admin.FailedLoginAttempts += 1;
        if (admin.FailedLoginAttempts >= MaxFailedAttempts)
        {
            admin.LockoutEndUtc = DateTime.UtcNow.Add(LockoutDuration);
        }

        admin.ModifyDate = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();

        var detail = admin.LockoutEndUtc.HasValue && admin.LockoutEndUtc > DateTime.UtcNow
            ? $"Failed attempt. Locked until {admin.LockoutEndUtc:O}"
            : "Failed attempt";

        await AddAuditLogAsync(admin.LoginId, eventType, false, detail, ipAddress);
    }

    private async Task<List<string>> GenerateRecoveryCodesInternalAsync(int adminId, int count)
    {
        var plainCodes = new List<string>();

        for (var i = 0; i < count; i++)
        {
            var plainCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            plainCodes.Add(plainCode);

            var saltBytes = RandomNumberGenerator.GetBytes(16);
            var hashBytes = Rfc2898DeriveBytes.Pbkdf2(plainCode, saltBytes, 100_000, HashAlgorithmName.SHA256, 32);

            dbContext.AdminRecoveryCodes.Add(new AdminRecoveryCodeEntity
            {
                AdminId = adminId,
                CodeSalt = Convert.ToBase64String(saltBytes),
                CodeHash = Convert.ToBase64String(hashBytes),
                CreateDate = DateTime.UtcNow,
                ModifyDate = DateTime.UtcNow
            });
        }

        await dbContext.SaveChangesAsync();
        return plainCodes;
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

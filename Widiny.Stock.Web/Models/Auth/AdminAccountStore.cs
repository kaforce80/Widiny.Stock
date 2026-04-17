using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Widiny.Stock.Web.Models.Auth;

public class AdminAccountStore
{
    private readonly object _syncRoot = new();
    private AdminAccount _admin;

    public AdminAccountStore(IOptions<AdminAuthOptions> options)
    {
        var config = options.Value;
        _admin = new AdminAccount
        {
            LoginId = string.IsNullOrWhiteSpace(config.LoginId) ? config.PrimaryEmail : config.LoginId,
            FirstName = config.FirstName,
            LastName = config.LastName,
            PrimaryEmail = string.IsNullOrWhiteSpace(config.PrimaryEmail) ? config.LoginId : config.PrimaryEmail,
            TotpSecretBase32 = string.IsNullOrWhiteSpace(config.TotpSecretBase32) ? TotpUtility.GenerateSecret() : config.TotpSecretBase32
        };

        SetPassword(config.Password);
    }

    public bool VerifyCredentials(string loginId, string password)
    {
        lock (_syncRoot)
        {
            if (!string.Equals(loginId, _admin.LoginId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return VerifyPassword(password, _admin.PasswordHash, _admin.PasswordSalt);
        }
    }

    public bool TryRegister(AdminRegisterViewModel model)
    {
        lock (_syncRoot)
        {
            if (string.Equals(model.LoginId, _admin.LoginId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            _admin.LoginId = model.LoginId;
            _admin.FirstName = model.FirstName;
            _admin.LastName = model.LastName;
            _admin.PrimaryEmail = model.PrimaryEmail;
            _admin.TotpSecretBase32 = TotpUtility.GenerateSecret();
            SetPassword(model.Password);
            return true;
        }
    }

    public string? GetTotpSecretByLoginId(string loginId)
    {
        lock (_syncRoot)
        {
            if (!string.Equals(loginId, _admin.LoginId, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return _admin.TotpSecretBase32;
        }
    }

    public string GetDisplayName(string loginId)
    {
        lock (_syncRoot)
        {
            if (!string.Equals(loginId, _admin.LoginId, StringComparison.OrdinalIgnoreCase))
            {
                return loginId;
            }

            return $"{_admin.FirstName} {_admin.LastName}".Trim();
        }
    }

    private void SetPassword(string password)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 100_000, HashAlgorithmName.SHA256, 32);

        _admin.PasswordSalt = Convert.ToBase64String(saltBytes);
        _admin.PasswordHash = Convert.ToBase64String(hashBytes);
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

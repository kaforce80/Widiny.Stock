using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Widiny.Stock.Web.Models.Entities;

[Table("Account.LoginHistory")]
public class LoginHistoryEntity : AuditableEntity
{
    [Key]
    public long Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string LoginId { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string UserName { get; set; } = string.Empty;

    public DateTime LoginDateUtc { get; set; }

    [MaxLength(256)]
    public string Browser { get; set; } = string.Empty;

    [MaxLength(64)]
    public string IpAddress { get; set; } = string.Empty;
}

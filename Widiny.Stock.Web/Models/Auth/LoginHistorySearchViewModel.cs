using Widiny.Stock.Web.Models.Entities;
using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class LoginHistorySearchViewModel
{
    [DataType(DataType.Date)]
    public DateTime FromDate { get; set; } = DateTime.UtcNow.Date.AddDays(-7);

    [DataType(DataType.Date)]
    public DateTime ToDate { get; set; } = DateTime.UtcNow.Date;

    public string? LoginId { get; set; }

    public string? UserName { get; set; }

    public string? Browser { get; set; }

    public string? IpAddress { get; set; }

    public List<LoginHistoryEntity> Results { get; set; } = [];
}

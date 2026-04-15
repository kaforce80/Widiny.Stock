namespace Widiny.Stock.Worker;

public class Worker(ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("Widiny.Stock.Worker heartbeat at: {time}", DateTimeOffset.Now);
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}

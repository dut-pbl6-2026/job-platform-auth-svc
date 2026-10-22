using System.Text.Json;
using SharedKernel.Events;
using SharedKernel.Kafka;

namespace SharedContract.Tests;

public class EventSchemaContractTests
{
    [Fact]
    public void ApplicationSubmitted_PreservesExistingWireContract()
    {
        // Consumer expectations stay fixed when shared changes.
        var applicationId = Guid.Parse(
            "11111111-1111-1111-1111-111111111111");
        var jobId = Guid.Parse(
            "22222222-2222-2222-2222-222222222222");
        var applicantId = Guid.Parse(
            "33333333-3333-3333-3333-333333333333");
        var occurredAt = new DateTime(
            2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var payload = new ApplicationSubmittedEvent(
            applicationId,
            jobId,
            "Backend Developer",
            applicantId,
            occurredAt);

        var envelope =
            EventEnvelope<ApplicationSubmittedEvent>.Create(
                ApplicationEventTypes.Submitted,
                payload);

        var json = JsonSerializer.Serialize(
            envelope,
            KafkaJson.Options);

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(
            "application.submitted",
            root.GetProperty("eventType").GetString());

        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.NotEqual(
            Guid.Empty,
            root.GetProperty("eventId").GetGuid());

        Assert.Equal(
            DateTimeKind.Utc,
            root.GetProperty("timestamp").GetDateTime().Kind);

        var data = root.GetProperty("payload");

        Assert.Equal(
            applicationId,
            data.GetProperty("applicationId").GetGuid());

        Assert.Equal(
            jobId,
            data.GetProperty("jobId").GetGuid());

        Assert.Equal(
            "Backend Developer",
            data.GetProperty("jobTitle").GetString());

        Assert.Equal(
            applicantId,
            data.GetProperty("applicantId").GetGuid());

        Assert.Equal(
            occurredAt,
            data.GetProperty("occurredAt").GetDateTime());
    }

    [Fact]
    public void ApplicationSubmitted_ReadsExistingV1Message()
    {
        const string json = """
    {
      "eventId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "eventType": "application.submitted",
      "version": 1,
      "timestamp": "2026-01-01T00:00:00Z",
      "payload": {
        "applicationId": "11111111-1111-1111-1111-111111111111",
        "jobId": "22222222-2222-2222-2222-222222222222",
        "jobTitle": "Backend Developer",
        "applicantId": "33333333-3333-3333-3333-333333333333",
        "occurredAt": "2026-01-01T00:00:00Z"
      }
    }
    """;

        var message =
            JsonSerializer.Deserialize<EventEnvelope<ApplicationSubmittedEvent>>(
                json,
                KafkaJson.Options);

        Assert.NotNull(message);

        Assert.Equal(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            message.EventId);

        Assert.Equal("application.submitted", message.EventType);
        Assert.Equal(1, message.Version);

        var expectedTime = new DateTime(
            2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        Assert.Equal(expectedTime, message.Timestamp);

        Assert.NotNull(message.Payload);

        Assert.Equal(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            message.Payload.ApplicationId);

        Assert.Equal(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            message.Payload.JobId);

        Assert.Equal("Backend Developer", message.Payload.JobTitle);

        Assert.Equal(
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            message.Payload.ApplicantId);

        Assert.Equal(expectedTime, message.Payload.OccurredAt);
    }
}
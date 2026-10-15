using SharedKernel.Events;

namespace SharedContract.Tests;

public class EventShapeContractTests
{
    [Fact]
    public void Events_PreserveRequiredConsumerFields()
    {
        var jobFields = new (string Name, Type Type)[]
        {
            ("JobId", typeof(Guid)),
            ("Title", typeof(string)),
            ("Description", typeof(string)),
            ("CompanyId", typeof(Guid)),
            ("CompanyName", typeof(string)),
            ("Location", typeof(string)),
            ("SalaryMin", typeof(decimal?)),
            ("SalaryMax", typeof(decimal?)),
            ("Currency", typeof(string)),
            ("CategoryId", typeof(Guid?)),
            ("CategoryName", typeof(string)),
            ("EmploymentType", typeof(string)),
            ("ExperienceLevel", typeof(string)),
            ("RecruiterId", typeof(Guid)),
            ("Requirements", typeof(string)),
            ("Benefits", typeof(string)),
            ("Status", typeof(string)),
            ("OccurredAt", typeof(DateTime))
        };

        AssertFields(typeof(JobCreatedEvent), jobFields);
        AssertFields(typeof(JobUpdatedEvent), jobFields);

        AssertFields(
            typeof(JobDeletedEvent),
            ("JobId", typeof(Guid)),
            ("OccurredAt", typeof(DateTime)));

        AssertFields(
            typeof(ApplicationSubmittedEvent),
            ("ApplicationId", typeof(Guid)),
            ("JobId", typeof(Guid)),
            ("JobTitle", typeof(string)),
            ("ApplicantId", typeof(Guid)),
            ("OccurredAt", typeof(DateTime)));

        AssertFields(
            typeof(ApplicationStatusChangedEvent),
            ("ApplicationId", typeof(Guid)),
            ("JobId", typeof(Guid)),
            ("JobTitle", typeof(string)),
            ("ApplicantId", typeof(Guid)),
            ("PreviousStatus", typeof(string)),
            ("NewStatus", typeof(string)),
            ("ChangedBy", typeof(Guid)),
            ("OccurredAt", typeof(DateTime)));
    }

    private static void AssertFields(
        Type eventType,
        params (string Name, Type Type)[] expectedFields)
    {
        foreach (var field in expectedFields)
        {
            var property = eventType.GetProperty(field.Name);

            Assert.True(
                property is not null,
                $"{eventType.Name}.{field.Name} was removed or renamed.");

            Assert.Equal(field.Type, property!.PropertyType);

            Assert.True(
                property.GetMethod?.IsPublic == true,
                $"{eventType.Name}.{field.Name} must remain readable.");
        }
    }
}
namespace Approov.Validation.Tests;

using Approov.Validation;
using StructuredFieldValues;

public sealed class StructuredFieldFormatterTests
{
    [Theory]
    [InlineData("?1")]
    [InlineData("?0")]
    [InlineData("42")]
    [InlineData("4.5")]
    [InlineData("\"hello \\\\\"")]
    [InlineData(":AQID:")]
    [InlineData("token")]
    public void SerializeItem_RoundTripsParsedItem(string raw)
    {
        var error = SfvParser.ParseItem(raw, out var item);

        Assert.False(error.HasValue, error?.Message ?? "Failed to parse item");
        Assert.Equal(raw, StructuredFieldFormatter.SerializeItem(item));
    }

    [Fact]
    public void SerializeList_RoundTripsParsedList()
    {
        var error = SfvParser.ParseList("abc, \"two\", ?1", out var list);

        Assert.False(error.HasValue, error?.Message ?? "Failed to parse list");
        Assert.Equal("abc, \"two\", ?1", StructuredFieldFormatter.SerializeList(list!));
    }

    [Fact]
    public void SerializeDictionary_RoundTripsParsedDictionary()
    {
        var error = SfvParser.ParseDictionary("a=1, b=\"two\", enabled", out var dictionary);

        Assert.False(error.HasValue, error?.Message ?? "Failed to parse dictionary");
        Assert.Equal("a=1, b=\"two\", enabled", StructuredFieldFormatter.SerializeDictionary(dictionary!));
    }

    [Fact]
    public void CombineHeaderValues_TrimsAndJoinsMultipleValues()
    {
        Assert.Equal("one,two", StructuredFieldFormatter.CombineHeaderValues(new[] { " one ", " two " }));
    }
}

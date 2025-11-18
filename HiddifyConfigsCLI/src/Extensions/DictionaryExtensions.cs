using System;
using System.Collections.Generic;

namespace HiddifyConfigsCLI.Utils
{
    public static class DictionaryExtensions
    {
        public static string? TryGet( this IDictionary<string, object> dict, string key )
        {
            return dict.TryGetValue(key, out var value)
                ? value?.ToString()
                : null;
        }

        public static int TryGetInt( this IDictionary<string, object> dict, string key, int defaultValue = 0 )
        {
            if (!dict.TryGetValue(key, out var value) || value == null)
                return defaultValue;

            if (int.TryParse(value.ToString(), out var result))
                return result;

            return defaultValue;
        }

        public static bool TryGetBool( this IDictionary<string, object> dict, string key, bool defaultValue = false )
        {
            if (!dict.TryGetValue(key, out var value) || value == null)
                return defaultValue;

            if (bool.TryParse(value.ToString(), out var result))
                return result;

            return defaultValue;
        }
    }
}

using System;
using System.Threading;

namespace HmacHttp
{
    public class uniqueDateTime
    {
        private static long lastTimeStamp = DateTime.UtcNow.Ticks;
        private static long UtcNowTicks
        {
            get
            {
                long original_value, new_value;
                do
                {
                    original_value = lastTimeStamp;
                    long now = DateTime.UtcNow.Ticks;
                    new_value = Math.Max(now, original_value + 1);
                } while (Interlocked.CompareExchange
                             (ref lastTimeStamp, new_value, original_value) != original_value);

                return new_value;
            }
        }
        public static DateTime NewDateTime
        {
            get
            {
                return new DateTime(UtcNowTicks);
            }
        }
    }
}
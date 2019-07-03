////////////////////////////////////////////////
// © https://github.com/badhitman - @fakegov 
////////////////////////////////////////////////
using System.Runtime.Serialization;

namespace HmacHttp
{
    public enum StatusResult
    {
        /// <summary>
        /// Не установлено (не известно)
        /// </summary>
        None,

        /// <summary>
        /// Ошибок не обнаружено
        /// </summary>
        Ok,

        /// <summary>
        /// Обнаружены ошибки. Смотрите в описании статуса и логах
        /// </summary>
        Err
    }
    [DataContract]
    public class ResultHmacResponseClass
    {
        [DataMember]
        public StatusResult status = StatusResult.None;

        [DataMember]
        public string StatusDescription;

        [DataMember]
        public string Response;
    }
}

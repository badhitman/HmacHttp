////////////////////////////////////////////////
// © https://github.com/badhitman - @fakegov 
////////////////////////////////////////////////
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace HmacHttp
{

    /// <summary>
    /// Состояния подписи запроса
    /// </summary>
    public enum StateHmacSign
    {
        /// <summary>
        /// Севреру не назначен HMAC валидатор
        /// </summary>
        NoSet,

        /// <summary>
        /// Подпись запроса не прошла проверку
        /// </summary>
        Error,

        /// <summary>
        /// Подпись запроса проверена
        /// </summary>
        Verified
    }

    public class HmacHttpWebRequest
    {
        /// <summary>
        /// Имя HTTP заголовка для передачи API auth-Key
        /// </summary>
        public static readonly string api_auth_key_prop_name = "Apiauth-Key";

        /// <summary>
        /// Имя HTTP заголовка для передачи API auth-Nonce
        /// </summary>
        public static readonly string api_auth_nonce_prop_name = "Apiauth-Nonce";

        /// <summary>
        /// Имя HTTP заголовка для передачи API auth-Signature
        /// </summary>
        public static readonly string api_auth_signature_prop_name = "Apiauth-Signature";
        //
        public readonly string hmac_auth_key;
        public readonly string hmac_auth_secret;

        /// <summary>
        /// Конструктор HMAC менеджера.
        /// </summary>
        /// <param name="my_hmac_auth_key">Дейсвительный HMAC auth-key</param>
        /// <param name="my_hmac_auth_secret">Дейсвительный HMAC auth-secret</param>
        public HmacHttpWebRequest(string my_hmac_auth_key, string my_hmac_auth_secret)
        {
            hmac_auth_key = my_hmac_auth_key;
            hmac_auth_secret = my_hmac_auth_secret;
        }

        #region Подписывание запроса/ответа
        /// <summary>
        /// Подписать запрос клиент->сервер
        /// </summary>
        public HttpWebRequest SignRequest(HttpWebRequest my_request)
        {
            string unixTimestamp = ((Int64)uniqueDateTime.NewDateTime.ToUniversalTime().Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();
            string message = unixTimestamp + hmac_auth_key + my_request.RequestUri.AbsolutePath;
            string signature = HashHMAC(message);
            //
            if (my_request.Headers[api_auth_key_prop_name] is null)
                my_request.Headers.Add(api_auth_key_prop_name, hmac_auth_key);
            else
                my_request.Headers[api_auth_key_prop_name] = hmac_auth_key;

            if (my_request.Headers[api_auth_nonce_prop_name] is null)
                my_request.Headers.Add(api_auth_nonce_prop_name, unixTimestamp);
            else
                my_request.Headers[api_auth_nonce_prop_name] = unixTimestamp;

            if (my_request.Headers[api_auth_signature_prop_name] is null)
                my_request.Headers.Add(api_auth_signature_prop_name, signature);
            else
                my_request.Headers[api_auth_signature_prop_name] = signature;
            //
            return my_request;
        }

        /// <summary>
        /// Подписать ответ север->клиент
        /// </summary>
        public HttpListenerResponse SignResponse(HttpListenerResponse response)
        {
            string unixTimestamp = ((Int64)uniqueDateTime.NewDateTime.ToUniversalTime().Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();

            if (response.Headers[api_auth_key_prop_name] is null)
                response.Headers.Add(api_auth_key_prop_name, hmac_auth_key);
            else
                response.Headers[api_auth_key_prop_name] = hmac_auth_key;

            if (response.Headers[api_auth_nonce_prop_name] is null)
                response.Headers.Add(api_auth_nonce_prop_name, unixTimestamp);
            else
                response.Headers[api_auth_nonce_prop_name] = unixTimestamp;

            string message = unixTimestamp + hmac_auth_key + response.ContentLength64;
            string signature = HashHMAC(message);

            if (response.Headers[api_auth_signature_prop_name] is null)
                response.Headers.Add(api_auth_signature_prop_name, signature);
            else
                response.Headers[api_auth_signature_prop_name] = signature;

            return response;
        }
        #endregion

        #region Проверка запроса/ответа
        /// <summary>
        /// Проверка подписи клиент-сервер
        /// </summary>
        public bool VerifyRequest(HttpListenerRequest my_request)
        {
            string inc_nonce = my_request.Headers[api_auth_nonce_prop_name];
            string inc_request_absolute_path = my_request.Url.AbsolutePath;
            string inc_signature = my_request.Headers[api_auth_signature_prop_name];

            return VerifiSignature(inc_nonce, inc_request_absolute_path, inc_signature);
        }

        /// <summary>
        /// Проверка подписи сервер->клиент
        /// </summary>
        public bool VerifyResponse(HttpWebResponse my_response)
        {
            string inc_nonce = my_response.Headers[api_auth_nonce_prop_name];
            string inc_signature = my_response.Headers[api_auth_signature_prop_name];
            
            return VerifiSignature(inc_nonce, my_response.ContentLength.ToString(), inc_signature);
        }
        #endregion

        /// <summary>
        /// Проверка HMAC подписи
        /// </summary>
        public bool VerifiSignature(string inc_nonce, string inc_salt, string inc_signature)
        {
            if (string.IsNullOrEmpty(hmac_auth_key) ||
                string.IsNullOrEmpty(hmac_auth_secret) ||
                
                string.IsNullOrEmpty(inc_nonce) ||
                string.IsNullOrEmpty(inc_salt) ||
                string.IsNullOrEmpty(inc_signature))
                return false;

            string message = inc_nonce + hmac_auth_key + inc_salt;
            string signature = HashHMAC(message);

            return signature == inc_signature;
        }

        #region HashHMAC
        private byte[] HashHMAC(byte[] bytes_hmac_auth_secret, byte[] bytes_message)
        {
            var hash = new HMACSHA256(bytes_hmac_auth_secret);
            return hash.ComputeHash(bytes_message);
        }

        private string HashHMAC(string message)
        {
            byte[] hash = HashHMAC(new ASCIIEncoding().GetBytes(hmac_auth_secret), new ASCIIEncoding().GetBytes(message));
            return BitConverter.ToString(hash).Replace("-", "").ToUpper(); ;
        }
        #endregion
    }
}

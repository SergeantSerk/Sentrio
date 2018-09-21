using System;
using System.Runtime.Serialization;

namespace Sentrio
{
    [Serializable]
    public class HMACNotEqualException : Exception
    {
        public HMACNotEqualException()
        {
        }

        public HMACNotEqualException(string message) : base(message)
        {
        }

        public HMACNotEqualException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected HMACNotEqualException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
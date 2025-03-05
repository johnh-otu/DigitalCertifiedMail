using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    internal class TCPAddressee
    {
        private string _ip;
        private int _port;

        public TCPAddressee(string ip, int port) 
        {
            _ip = ip;
            _port = port;
        }
        
        public string GetIP() {  return _ip; }
        public int GetPort() { return _port; }
    }
}

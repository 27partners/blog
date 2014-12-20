using CommandLine.Utility;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

/* LICENSE/COPYRIGHT APPLIES ONLY TO NAMESPACE 'UdpTrace'
Copyright 2010 Chris Lloyd. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY CHRIS LLOYD ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CHRIS LLOYD OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the
authors and should not be interpreted as representing official policies, either expressed
or implied, of Chris Lloyd.
*/

namespace udptrace {
    class Program {
        static void Main(string[] args) {
            if (args.Length == 0)
                usage();
            Arguments cl = new Arguments(args);
            string[] hostport = args[args.Length - 1].Split(':');
            if (hostport.Length < 2)
                usage();
            string remoteHost = hostport[0];
            int remotePort = 0;
            try {
                remotePort = int.Parse(hostport[1]);
            } catch (FormatException) {
                Console.WriteLine("Port '{0}' is not a number", hostport[1]);
                Environment.Exit(1);
            }

            short maxHops = (cl["h"] != null) ? short.Parse(cl["h"]) : (short)20;
            int packetSize = (cl["s"] != null) ? int.Parse(cl["s"]) : 52;
            int receiveTimeout = (cl["w"] != null) ? int.Parse(cl["w"]) : 3000;

            if (packetSize < 1) {
                Console.WriteLine("Packet size {0} is too small", packetSize);
                Environment.Exit(1);
            }

            IPEndPoint remoteIPEndPoint = null;
            try {
                foreach (IPAddress ip in Dns.GetHostEntry(remoteHost).AddressList) {
                    if (ip.AddressFamily == AddressFamily.InterNetwork) {
                        remoteIPEndPoint = new IPEndPoint(BitConverter.ToUInt32(ip.GetAddressBytes(), 0), remotePort);
                        break;
                    } else {
                        continue;
                    }
                }
            } catch (SocketException e) {
                if (e.SocketErrorCode == SocketError.HostNotFound) {
                    Console.WriteLine("Unable to resolve target system name {0}", remoteHost);
                } else {
                    Console.WriteLine("Unknown socket error {0}: '{1}'", e.ErrorCode, e.Message);
                }
                Environment.Exit(1);
            }
            if (remoteIPEndPoint == null) {
                Console.WriteLine("No IPv4 address found for {0}", remoteHost);
                Environment.Exit(1);
            }

            UdpClient udp = new UdpClient();
            udp.Connect(remoteIPEndPoint);
            IPEndPoint localIPEndPoint = (IPEndPoint)udp.Client.LocalEndPoint;
            if (cl["l"] != null) {
                try {
                    localIPEndPoint.Port = int.Parse(cl["l"]);
                } catch (FormatException) {
                    Console.WriteLine("Packet size {0} is not a number", packetSize);
                    Environment.Exit(1);
                }
            }
            udp.Close();

            Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
            udpSocket.Bind(localIPEndPoint);
            Socket icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            icmpSocket.ReceiveTimeout = receiveTimeout;
            icmpSocket.Bind(localIPEndPoint);
            udpSocket.Connect(remoteIPEndPoint);

            byte[] packet = new byte[packetSize];
            for (int i = 0; i < 2; i++) {
                packet[1 - i] = (byte)((localIPEndPoint.Port >> 8 * i) & 0xFF);
                packet[3 - i] = (byte)((remoteIPEndPoint.Port >> 8 * i) & 0xFF);
            }
            packet[5] = (byte)packet.Length;
            packet[6] = 0;
            packet[7] = 0;

            Console.WriteLine(@"
Tracing route to {0} [{1}]
using {2} byte packets, from local port {3}, over a maximum of {4} hops:
", remoteHost, remoteIPEndPoint.Address.ToString(), packetSize, localIPEndPoint.Port, maxHops);

            for (udpSocket.Ttl = 1; udpSocket.Ttl < maxHops; udpSocket.Ttl++) {
                Console.Write("{0,3}\t", udpSocket.Ttl);
                Byte[] buffer = null;
                for (int i = 0; i < 3; i++) {
                    long t = DateTime.Now.Ticks;
                    packet[8] = (byte)udpSocket.Ttl;
                    udpSocket.Send(packet, packet.Length, SocketFlags.None);
                    buffer = new Byte[256];
                    try {
                        icmpSocket.Receive(buffer, SocketFlags.None);
                    } catch (SocketException) {
                        Console.Write("*\t");
                        buffer = null;
                        continue;
                    }
                    t = DateTime.Now.Ticks - t;
                    Console.Write("{0} ms\t", t / 10000);
                }

                if (buffer == null) {
                    Console.WriteLine("Request timed out");
                    continue;
                }

                IPAddress remoteIPAddress = new IPAddress((uint)((buffer[15] << 24) | (buffer[14] << 16) | (buffer[13] << 8) | buffer[12]));
                string remoteHostName = remoteIPAddress.ToString();
                IPHostEntry entry = new IPHostEntry();
                try {
                    remoteHostName = Dns.GetHostEntry(remoteIPAddress).HostName;
                } catch (SocketException) { }

                Console.Write("{0} ({1}) ", remoteHostName, remoteIPAddress.ToString());

                switch (buffer[20]) {
                    case 11:
                        if (buffer[56] == 0)
                            Console.Write("(datagram stripped)");
                        else if (buffer[56] != udpSocket.Ttl)
                            Console.Write("(out of sequence - ttl {0})", buffer[56]);
                        break;
                    case 3:
                        Console.Write("ICMP dest unreachable (code {0})", buffer[21]);
                        udpSocket.Ttl = maxHops;
                        break;
                    default:
                        Console.Write("ICMP type: {0}, code: {1}", buffer[20], buffer[21]);
                        break;
                }
                Console.WriteLine();
            }
        }

        static void usage() {
            Console.WriteLine(
@"Usage: udptrace [-d] [-h maximum_hops] [-w timeout] [-l localport] [-s size] target_name:remote_port

Options:
    -d                 Do not resolve addresses to hostnames.
    -h maximum_hops    Maximum number of hops to search for target.
    -w timeout         Wait timeout milliseconds for each reply.
    -l localport       Local port number.
    -s size            Payload size.");
            Environment.Exit(1);
        }
    }
}

namespace CommandLine.Utility {
    public class Arguments {
        private StringDictionary Parameters;

        public Arguments(string[] Args) {
            Parameters = new StringDictionary();
            Regex Spliter = new Regex(@"^-{1,2}|^/|=|:", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            Regex Remover = new Regex(@"^['""]?(.*?)['""]?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            string Parameter = null;
            string[] Parts;
            foreach (string Txt in Args) {
                Parts = Spliter.Split(Txt, 3);
                switch (Parts.Length) {
                    case 1:
                        if (Parameter != null) {
                            if (!Parameters.ContainsKey(Parameter)) {
                                Parts[0] = Remover.Replace(Parts[0], "$1");
                                Parameters.Add(Parameter, Parts[0]);
                            }
                            Parameter = null;
                        }
                        break;
                    case 2:
                        if (Parameter != null)
                            if (!Parameters.ContainsKey(Parameter)) Parameters.Add(Parameter, "true");
                        Parameter = Parts[1];
                        break;
                    case 3:
                        if (Parameter != null) {
                            if (!Parameters.ContainsKey(Parameter))
                                Parameters.Add(Parameter, "true");
                        }
                        Parameter = Parts[1];
                        if (!Parameters.ContainsKey(Parameter)) {
                            Parts[2] = Remover.Replace(Parts[2], "$1");
                            Parameters.Add(Parameter, Parts[2]);
                        }
                        Parameter = null;
                        break;
                }
            }
            if (Parameter != null) {
                if (!Parameters.ContainsKey(Parameter))
                    Parameters.Add(Parameter, "true");
            }
        }

        public string this[string Param] {
            get {
                return (Parameters[Param]);
            }
        }
    }
}

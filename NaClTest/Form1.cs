using NAudio.Wave;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Altus.Saltable;

namespace NaClTest
{
    public partial class Form1 : Form
    {
        WaveIn _wave;
        WaveOut _waveOut;
        BufferedWaveProvider _playback;
        NaClClient _clientA;
        NaClClient _clientB;
        Stopwatch _sw;
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            byte[] apk, ask, bpk, bsk;
            NaClClient.CreateKeys(out apk, out ask);
            NaClClient.CreateKeys(out bpk, out bsk);

            var hasher = System.Security.Cryptography.SHA256.Create();
            
            _clientA = NaClClient.Create(apk, ask, bpk);
            _clientB = NaClClient.Create(bpk, bsk, apk);

            _sw = new Stopwatch();
            _sw.Start();

            _wave = new WaveIn(this.Handle);
            _wave.WaveFormat = new WaveFormat(12000, 8, 1);
            _wave.BufferMilliseconds = 100;
            _wave.DataAvailable += _wave_DataAvailable;
            _wave.StartRecording();

            _playback = new BufferedWaveProvider(_wave.WaveFormat);

            _waveOut = new WaveOut();
            _waveOut.DesiredLatency = 100;
            _waveOut.Init(_playback);
            _waveOut.Play();
        }

        void _wave_DataAvailable(object sender, WaveInEventArgs e)
        {
            Debug.WriteLine(e.BytesRecorded + " bytes, " + _sw.ElapsedTicks / TimeSpan.TicksPerMillisecond);
            _sw.Reset();
            _sw.Start();
            byte[] clear = e.Buffer;
            byte[] nonce;
            byte[] cipher = _clientA.Encrypt(e.Buffer, 0, e.BytesRecorded, out nonce);
            clear = _clientB.Decrypt(cipher, nonce);
            _playback.AddSamples(clear, 0, clear.Length);
        }
    }
}

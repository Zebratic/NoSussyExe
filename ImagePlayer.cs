using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ImagePlayer
{
    public class ImagePlayer
    {
        /*
         *  ImagePlayer made by Zebratic#6969
         *  A Gif to Console player (ASCII)
         */

        public Image IMG { get; set; }
        public int FRAMECOUNT { get; set; }
        public int WIDTH = -1;
        public int HEIGHT = -1;
        public int SCALE = -1;
        public List<string> DATA { get; set; }
        public char[] CHARS = { '#', '#', '@', '%', '=', '+', '*', ':', '-', '.', ' ' };
    }

    public static class Extensions
    {
        public static void SetScale(this ImagePlayer player, int scale)
        {
            player.SCALE = scale;
        }

        public static void SetSize(this ImagePlayer player, int width, int height)
        {
            player.WIDTH = width - 1;
            player.HEIGHT = height - 2;
        }

        public static bool LoadSource(this ImagePlayer player, object source)
        {
            if (source.GetType() == typeof(string))
            {
                WebClient wc = new WebClient();
                byte[] data = wc.DownloadData((string)source);
                using (MemoryStream stream = new MemoryStream(data))
                {
                    using (Image img = Image.FromStream(stream))
                    {
                        player.IMG = img;
                        if (player.SCALE != -1)
                        {
                            player.WIDTH = (int)(double)(player.IMG.Width * ((double)player.SCALE / 100));
                            player.HEIGHT = (int)(double)(player.IMG.Height * ((double)player.SCALE / 100));
                        }
                        else if (player.WIDTH != -1 && player.HEIGHT != -1) { }
                        else { return false; }


                        player.DATA = player.GetData(out int framecount);
                        player.FRAMECOUNT = framecount;
                        return true;
                    }
                }
            }
            else if (source.GetType() == typeof(Image))
            {
                player.IMG = (Image)source;
                if (player.SCALE != -1)
                {
                    player.WIDTH = (int)(double)(player.IMG.Width * ((double)player.SCALE / 100));
                    player.HEIGHT = (int)(double)(player.IMG.Height * ((double)player.SCALE / 100));
                }
                else if (player.WIDTH != -1 && player.HEIGHT != -1) { }
                else { return false; }

                player.DATA = player.GetData(out int framecount);
                player.FRAMECOUNT = framecount;
                return true;
            }
            else { return false; }
        }

        public static void PrintImage(this ImagePlayer player, int speed, bool loopgif = false, bool checkforresize = false, int cursorLeft = -1, int cursorTop = -1)
        {
            int Left = Console.CursorLeft, Top = Console.CursorTop;
            if (cursorLeft != -1 || cursorTop != -1)
            {
                Left = cursorLeft;
                Top = cursorTop;
            }

            if (checkforresize)
                new Thread(() => CheckForResize(Left, Top)).Start();

            try { Console.SetBufferSize((player.IMG.Width * 0x2) + Left, (player.IMG.Height * 0x2) + Top); } catch { }

            redo:
            for (int i = 0; i < player.FRAMECOUNT; i++)
            {
                string fixeddata = "";
                foreach (string data in player.DATA[i].Split('\n'))
                    fixeddata += "\n".PadRight(Left) + data;

                Console.SetCursorPosition(Left, Top);
                Console.Write(fixeddata);
                Thread.Sleep(speed);
            }
            if (loopgif)
                goto redo;
        }

        private static void CheckForResize(int Left, int Top)
        {
            int width = Console.WindowWidth;
            int height = Console.WindowHeight;
            while (true)
            {
                if (width != Console.WindowWidth || height != Console.WindowHeight)
                {
                    width = Console.WindowWidth;
                    height = Console.WindowHeight;
                    Console.Clear();
                    Console.SetCursorPosition(Left, Top);
                }
                Thread.Sleep(10);
            }
        }

        private static Image ResizeImage(this Image img, int width, int height)
        {
            var destRect = new Rectangle(0, 0, width, height);
            var destImage = new Bitmap(width, height);

            destImage.SetResolution(img.HorizontalResolution, img.VerticalResolution);

            using (var graphics = Graphics.FromImage(destImage))
            {
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.CompositingQuality = CompositingQuality.HighQuality;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.SmoothingMode = SmoothingMode.HighQuality;
                graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;

                using (var wrapMode = new ImageAttributes())
                {
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    graphics.DrawImage(img, destRect, 0, 0, img.Width, img.Height, GraphicsUnit.Pixel, wrapMode);
                }
            }

            return destImage;
        }


        private static List<Image> GetFrames(this Image img, int width, int height)
        {
            List<Image> IMGs = new List<Image>();

            try
            {
                int frameCount = img.GetFrameCount(FrameDimension.Time);
                for (int i = 0; i < frameCount; i++)
                {
                    img.SelectActiveFrame(FrameDimension.Time, i);
                    if (width != -1 && height != -1)
                    {
                        Bitmap frame = new Bitmap(new Bitmap(img).ResizeImage(width, height));
                        IMGs.Add(frame);
                    }
                    else
                    {
                        IMGs.Add(new Bitmap(img));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                if (width != -1 && height != -1)
                {
                    Bitmap frame = new Bitmap(new Bitmap(img).ResizeImage(width, height));
                    IMGs.Add(frame);
                }
                else
                {
                    IMGs.Add(new Bitmap(img));
                }
            }

            return IMGs;
        }

        public static List<string> GetData(this ImagePlayer player, out int framecount)
        {
            List<string> data = new List<string>();

            framecount = 0;

            List<Image> frames = player.IMG.GetFrames(player.WIDTH, player.HEIGHT);

            foreach (Image frame in frames)
            {
                string temp = "";
                for (int i = 0x0; i < player.HEIGHT; i++)
                {
                    for (int x = 0x0; x < player.WIDTH; x++)
                    {
                        Color Color = ((Bitmap)frame).GetPixel(x, i);
                        if (Color.A == 0 || Color.IsEmpty)
                        {
                            temp += player.CHARS[10];
                        }
                        else
                        {
                            int Gray = (Color.R + Color.G + Color.B) / 0x3;
                            int Index = (Gray * (player.CHARS.Length - 0x1)) / 0xFF;
                            temp += player.CHARS[Index];
                        }
                    }
                    temp += "\n";
                }
                data.Add(temp);
                framecount++;
            }

            return data;
        }
    }
}
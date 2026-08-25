using System.Net;
using System.Net.Http.Json;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class SettingsForm : Form
{
    readonly TextBox _virusTotal = SecretBox(), _abuseCh = SecretBox();
    readonly Label _vtStatus = StatusLabel(), _abuseChStatus = StatusLabel();
    readonly Color _bg = Color.FromArgb(7, 12, 20), _panel = Color.FromArgb(14, 23, 36), _orange = Color.FromArgb(255, 116, 22), _cyan = Color.FromArgb(73, 200, 255);

    public SettingsForm()
    {
        Text = "GivenX Shield | Inteligencia y credenciales"; Size = new(760, 560); MinimumSize = new(720, 530); StartPosition = FormStartPosition.CenterParent; BackColor = _bg; ForeColor = Color.White; Font = new("Segoe UI", 10);
        var title = new Label { Text = "MOTORES DE INTELIGENCIA", Font = new("Segoe UI Semibold", 20), ForeColor = _orange, AutoSize = true, Left = 28, Top = 24 }; Controls.Add(title);
        Controls.Add(new Label { Text = "Las claves se cifran con DPAPI y quedan vinculadas a tu usuario de Windows.", ForeColor = _cyan, AutoSize = true, Left = 30, Top = 70 });
        var vt = EnginePanel("VIRUSTOTAL", "Consulta reputación mediante SHA-256. Nunca sube archivos automáticamente.", _virusTotal, _vtStatus, 110, TestVirusTotalAsync, "virustotal"); Controls.Add(vt);
        var abuse = EnginePanel("ABUSE.CH", "Una Auth-Key para ThreatFox, URLhaus, YARAify y MalwareBazaar.", _abuseCh, _abuseChStatus, 285, TestAbuseChAsync, "abusech"); Controls.Add(abuse);
        _virusTotal.Text = SecureSecrets.Load("virustotal") ?? "";
        _abuseCh.Text = SecureSecrets.Load("abusech") ?? SecureSecrets.Load("threatfox") ?? "";
        _vtStatus.Text = SecureSecrets.Exists("virustotal") ? "CONFIGURADA" : "REQUIERE CLAVE";
        _abuseChStatus.Text = !string.IsNullOrWhiteSpace(_abuseCh.Text) ? "CONFIGURADA" : "REQUIERE CLAVE";
    }

    Panel EnginePanel(string name, string description, TextBox box, Label status, int top, Func<string,Task<ApiTest>> tester, string secretName)
    {
        var panel = new Panel { Left = 28, Top = top, Width = 645, Height = 150, BackColor = _panel };
        panel.Controls.Add(new Label { Text = name, Font = new("Segoe UI Semibold", 13), ForeColor = _cyan, AutoSize = true, Left = 18, Top = 14 });
        panel.Controls.Add(new Label { Text = description, ForeColor = Color.FromArgb(165,184,207), AutoSize = true, Left = 18, Top = 43 });
        box.Left = 18; box.Top = 73; box.Width = 375; panel.Controls.Add(box);
        status.Left = 410; status.Top = 77; panel.Controls.Add(status);
        var save = Button("GUARDAR", 18, 111); save.Click += (_,_) => { SecureSecrets.Save(secretName, box.Text.Trim()); if(secretName=="abusech")SecureSecrets.Delete("threatfox"); status.Text = "GUARDADA"; status.ForeColor = Color.FromArgb(66,226,151); }; panel.Controls.Add(save);
        var test = Button("PROBAR", 130, 111); test.Click += async (_,_) => { status.Text = "PROBANDO..."; var result = await tester(box.Text.Trim()); status.Text = result.Text; status.ForeColor = result.Color; }; panel.Controls.Add(test);
        var delete = Button("BORRAR", 242, 111); delete.Click += (_,_) => { if (MessageBox.Show($"¿Borrar la clave de {name}?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) { SecureSecrets.Delete(secretName); if(secretName=="abusech")SecureSecrets.Delete("threatfox"); box.Clear(); status.Text="REQUIERE CLAVE"; status.ForeColor=Color.FromArgb(255,190,70); } }; panel.Controls.Add(delete);
        return panel;
    }

    async Task<ApiTest> TestVirusTotalAsync(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return ApiTest.Missing;
        try
        {
            using var http = Client(); http.DefaultRequestHeaders.Add("x-apikey", key);
            using var response = await http.GetAsync("https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
            return FromStatus(response.StatusCode);
        }
        catch { return ApiTest.Offline; }
    }

    async Task<ApiTest> TestAbuseChAsync(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return ApiTest.Missing;
        try
        {
            using var http = Client(); http.DefaultRequestHeaders.Add("Auth-Key", key);
            using var response = await http.PostAsJsonAsync("https://threatfox-api.abuse.ch/api/v1/", new { query = "types" });
            if(response.StatusCode!=HttpStatusCode.OK)return FromStatus(response.StatusCode);
            using var json=System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
            var queryStatus=json.RootElement.TryGetProperty("query_status",out var value)?value.GetString():null;
            return string.Equals(queryStatus,"ok",StringComparison.OrdinalIgnoreCase)?ApiTest.Connected:
                queryStatus is "no_api_key" or "user_blacklisted"?ApiTest.Invalid:new($"ERROR {queryStatus??"RESPUESTA"}",Color.FromArgb(255,73,91));
        }
        catch { return ApiTest.Offline; }
    }

    static ApiTest FromStatus(HttpStatusCode status) => status switch
    {
        HttpStatusCode.OK => ApiTest.Connected,
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => ApiTest.Invalid,
        HttpStatusCode.TooManyRequests => ApiTest.Limited,
        _ => new($"ERROR {(int)status}", Color.FromArgb(255,73,91))
    };
    static HttpClient Client() { var h = new HttpClient { Timeout = TimeSpan.FromSeconds(20) }; h.DefaultRequestHeaders.UserAgent.ParseAdd("GivenX-Shield-Beta/1.6.2-R9 defensive-security"); return h; }
    Button Button(string text, int left, int top) => new() { Text=text, Left=left, Top=top, Width=100, Height=28, FlatStyle=FlatStyle.Flat, BackColor=Color.FromArgb(25,39,58), ForeColor=Color.White, FlatAppearance={BorderColor=_orange} };
    static TextBox SecretBox() => new() { UseSystemPasswordChar=true, BackColor=Color.FromArgb(8,15,25), ForeColor=Color.White, BorderStyle=BorderStyle.FixedSingle };
    static Label StatusLabel() => new() { Text="REQUIERE CLAVE", ForeColor=Color.FromArgb(255,190,70), AutoSize=true };
    readonly record struct ApiTest(string Text, Color Color)
    {
        public static ApiTest Connected => new("CONECTADO", Color.FromArgb(66,226,151));
        public static ApiTest Invalid => new("CLAVE INVÁLIDA", Color.FromArgb(255,73,91));
        public static ApiTest Limited => new("LÍMITE ALCANZADO", Color.FromArgb(255,190,70));
        public static ApiTest Offline => new("SIN CONEXIÓN", Color.FromArgb(255,190,70));
        public static ApiTest Missing => new("REQUIERE CLAVE", Color.FromArgb(255,190,70));
    }
}

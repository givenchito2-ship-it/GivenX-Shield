using System.Diagnostics;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class ConnectionsForm:Form
{
    sealed record RowTag(LiveConnection Connection,bool KnownIndicator);
    readonly ListView _list=new(){Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,GridLines=false,BackColor=Color.FromArgb(9,16,26),ForeColor=Color.White};
    readonly Label _status=new(){Dock=DockStyle.Bottom,Height=34,ForeColor=Color.FromArgb(73,200,255),Padding=new(14,8,0,0)};
    readonly CheckBox _automatic=new(){Text="BLOQUEAR AUTOMÁTICAMENTE IP CONFIRMADA",AutoSize=true,ForeColor=Color.White,Margin=new(16,9,8,0)};
    readonly System.Windows.Forms.Timer _timer=new(){Interval=5000};readonly Color _orange=Color.FromArgb(255,116,22);bool _refreshing,_loading;

    public ConnectionsForm()
    {
        Text="GivenX Shield | Conexiones y respuesta";Size=new(1260,720);MinimumSize=new(1080,620);StartPosition=FormStartPosition.CenterParent;BackColor=Color.FromArgb(7,12,20);ForeColor=Color.White;Font=new("Segoe UI",10);
        _list.Columns.Add("Proceso",170);_list.Columns.Add("PID",70);_list.Columns.Add("Dirección local",190);_list.Columns.Add("Dirección remota",220);_list.Columns.Add("Estado",105);_list.Columns.Add("Inteligencia",150);_list.Columns.Add("Ruta",420);
        var tools=new FlowLayoutPanel{Dock=DockStyle.Top,Height=96,Padding=new(12,10,0,0),BackColor=Color.FromArgb(14,23,36),WrapContents=true};
        var refresh=Button("ACTUALIZAR",110);refresh.Click+=async(_,_)=>await RefreshRowsAsync();tools.Controls.Add(refresh);
        var ip=Button("BLOQUEAR IP",125);ip.Click+=async(_,_)=>await BlockIp();tools.Controls.Add(ip);
        var program=Button("BLOQUEAR PROGRAMA",170);program.Click+=async(_,_)=>await BlockProgram();tools.Controls.Add(program);
        var contain=Button("CONTENER IOC",135);contain.Click+=async(_,_)=>await Contain();tools.Controls.Add(contain);
        var terminate=Button("FINALIZAR",110);terminate.Click+=(_,_)=>Terminate();tools.Controls.Add(terminate);
        var location=Button("UBICACIÓN",110);location.Click+=(_,_)=>OpenLocation();tools.Controls.Add(location);
        var blocks=Button("BLOQUEOS / HISTORIAL",190);blocks.Click+=(_,_)=>new NetworkBlocksForm().ShowDialog(this);tools.Controls.Add(blocks);
        tools.Controls.Add(_automatic);Controls.Add(_list);Controls.Add(_status);Controls.Add(tools);tools.BringToFront();_status.BringToFront();
        _loading=true;_automatic.Checked=ResponseConfigurationStore.Read().AutoBlockConfirmedConnections;_loading=false;
        _automatic.CheckedChanged+=(_,_)=>ChangeAutomaticResponse();
        Shown+=async(_,_)=>await RefreshRowsAsync();_timer.Tick+=async(_,_)=>await RefreshRowsAsync();_timer.Start();
    }

    Button Button(string text,int width)=>new(){Text=text,Width=width,Height=34,FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(25,39,58),ForeColor=Color.White,FlatAppearance={BorderColor=_orange}};
    RowTag? Selected()=>_list.SelectedItems.Count==0?null:_list.SelectedItems[0].Tag as RowTag;

    async Task RefreshRowsAsync()
    {
        if(_refreshing)return;_refreshing=true;try
        {
            _status.Text="Leyendo conexiones TCP y relacionándolas con sus procesos…";var snapshot=await Task.Run(()=>ConnectionInspector.Snapshot());var indicators=ThreatIndicatorStore.ReadHosts();var rows=snapshot.Where(x=>x.IsEstablished&&x.Remote.Port>0).ToList();
            _list.BeginUpdate();try{_list.Items.Clear();foreach(var row in rows)
            {
                var remote=row.Remote.Address.ToString();var known=indicators.Contains(remote);var item=new ListViewItem(row.ProcessName);item.SubItems.Add(row.ProcessId.ToString());item.SubItems.Add(row.Local.ToString());item.SubItems.Add(row.Remote.ToString());item.SubItems.Add("ESTABLECIDA");item.SubItems.Add(known?"IOC MALICIOSO":"SIN COINCIDENCIA");item.SubItems.Add(row.ProcessPath);item.Tag=new RowTag(row,known);item.ForeColor=known?Color.FromArgb(255,73,91):FirewallResponse.IsPublicAddress(row.Remote.Address)?Color.White:Color.FromArgb(150,170,195);_list.Items.Add(item);
            }
            }finally{_list.EndUpdate();}var knownCount=_list.Items.Cast<ListViewItem>().Count(x=>x.Tag is RowTag tag&&tag.KnownIndicator);_status.Text=$"{rows.Count:N0} conexiones establecidas · {knownCount} coincidencias IOC · no coincidir no significa que una conexión sea segura.";
        }
        catch(Exception ex){_status.Text="No se pudieron leer las conexiones: "+ex.Message;}finally{_refreshing=false;}
    }

    async Task BlockIp()
    {
        var selected=Selected();if(selected is null)return;var address=selected.Connection.Remote.Address;
        if(!FirewallResponse.IsPublicAddress(address)){MessageBox.Show(this,"GivenX no bloqueará una dirección local, privada o de sistema.","Bloqueo rechazado",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}
        if(MessageBox.Show(this,$"Se bloqueará toda conexión saliente hacia {address}. La acción es reversible. ¿Continuar?","Bloquear IP",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        try{var row=await FirewallResponse.BlockRemoteAddressAsync(address.ToString());MessageBox.Show(this,"IP bloqueada.\n"+row.RuleName,"GivenX Shield");}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"No se pudo bloquear",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }

    async Task BlockProgram()
    {
        var selected=Selected();var path=selected?.Connection.ProcessPath;if(string.IsNullOrWhiteSpace(path)||!File.Exists(path)){MessageBox.Show(this,"No se pudo obtener el ejecutable propietario.","GivenX Shield");return;}
        if(MessageBox.Show(this,$"Se bloquearán las conexiones salientes de:\n{path}\n\nLa acción es reversible. ¿Continuar?","Bloquear programa",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        try{var row=await FirewallResponse.BlockAsync(path);MessageBox.Show(this,"Programa bloqueado.\n"+row.RuleName,"GivenX Shield");}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"No se pudo bloquear",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }

    async Task Contain()
    {
        var selected=Selected();if(selected is null)return;if(!selected.KnownIndicator){MessageBox.Show(this,"La contención conjunta se habilita únicamente cuando la IP coincide con la inteligencia local. Puedes bloquear manualmente la IP o el programa.","Sin coincidencia IOC",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}
        var c=selected.Connection;var warning=$"La IP {c.Remote.Address} coincide con inteligencia maliciosa. GivenX intentará:\n\n• bloquear la IP;\n• bloquear el ejecutable si está en una carpeta de usuario;\n• finalizar su PID verificado;\n• cifrar el archivo en cuarentena.\n\nPuede perderse trabajo no guardado. ¿CONTINUAR?";
        if(MessageBox.Show(this,warning,"Contención avanzada",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        var result=await ContainmentService.ContainAsync(new(c.ProcessPath,c.ProcessId,c.Remote.Address.ToString(),"Conexión con IOC confirmado"));var title=result.Completed?"Contención completa":result.AnyAction?"Contención parcial":"Contención no completada";MessageBox.Show(this,result.Summary,title,MessageBoxButtons.OK,result.Completed?MessageBoxIcon.Information:MessageBoxIcon.Warning);await RefreshRowsAsync();
    }

    void Terminate()
    {
        var selected=Selected();if(selected is null||string.IsNullOrWhiteSpace(selected.Connection.ProcessPath))return;var c=selected.Connection;
        if(MessageBox.Show(this,$"Se finalizará {c.ProcessName} (PID {c.ProcessId}). Puede perderse trabajo no guardado. ¿Continuar?","Finalizar proceso",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        try{ProcessResponse.TerminateUserProcess(c.ProcessId,c.ProcessPath);MessageBox.Show(this,"Proceso finalizado.","GivenX Shield");}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"No se finalizó",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }

    void OpenLocation(){var path=Selected()?.Connection.ProcessPath;if(string.IsNullOrWhiteSpace(path)||!File.Exists(path))return;try{var start=new ProcessStartInfo("explorer.exe"){UseShellExecute=true};start.ArgumentList.Add("/select,");start.ArgumentList.Add(path);Process.Start(start);}catch{}}

    void ChangeAutomaticResponse()
    {
        if(_loading)return;if(_automatic.Checked&&MessageBox.Show(this,"El modo automático bloqueará solamente IP públicas que coincidan exactamente con la inteligencia descargada. No finalizará procesos ni aislará archivos sin preguntarte. ¿Activarlo?","Respuesta automática",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes){_loading=true;_automatic.Checked=false;_loading=false;return;}
        ResponseConfigurationStore.Write(new(_automatic.Checked));ResponseActionStore.Append("Configurar respuesta automática","Bloqueo de IP confirmada",_automatic.Checked?"ACTIVADA":"DESACTIVADA",false,"Cambio confirmado desde la interfaz");_status.Text=_automatic.Checked?"Respuesta automática activada.":"Respuesta automática desactivada; las acciones serán manuales.";
    }

    protected override void Dispose(bool disposing){if(disposing)_timer.Dispose();base.Dispose(disposing);}
}

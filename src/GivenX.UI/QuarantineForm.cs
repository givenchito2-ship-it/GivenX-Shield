using System.Security.Cryptography;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class QuarantineForm : Form
{
    readonly ListView _list=new(){Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,BackColor=Color.FromArgb(9,16,26),ForeColor=Color.White};
    readonly Color Orange=Color.FromArgb(255,116,22);
    public QuarantineForm()
    {
        Text="GivenX Shield | Cuarentena";Size=new(900,560);StartPosition=FormStartPosition.CenterParent;BackColor=Color.FromArgb(7,12,20);ForeColor=Color.White;Font=new("Segoe UI",10);
        _list.Columns.Add("Fecha",145);_list.Columns.Add("Archivo original",330);_list.Columns.Add("SHA-256",180);_list.Columns.Add("Tamaño",90);_list.Columns.Add("Motivo",240);
        var bar=new FlowLayoutPanel{Dock=DockStyle.Top,Height=60,Padding=new(14,12,0,0),BackColor=Color.FromArgb(14,23,36)};
        var restore=Button("RESTAURAR");restore.Click+=async(_,_)=>await RestoreSelected();bar.Controls.Add(restore);
        var allow=Button("PERMITIR ARCHIVO");allow.Click+=async(_,_)=>await AllowFile();bar.Controls.Add(allow);
        var quarantine=Button("AISLAR ARCHIVO...");quarantine.Click+=async(_,_)=>await QuarantineFile();bar.Controls.Add(quarantine);
        var network=Button("BLOQUEAR RED...");network.Click+=async(_,_)=>await BlockNetwork();bar.Controls.Add(network);
        var blocks=Button("VER BLOQUEOS");blocks.Click+=(_,_)=>new NetworkBlocksForm().ShowDialog(this);bar.Controls.Add(blocks);
        Controls.Add(_list);Controls.Add(bar);LoadRows();
    }
    Button Button(string text)=>new(){Text=text,Width=145,Height=34,FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(25,39,58),ForeColor=Color.White,FlatAppearance={BorderColor=Orange}};
    void LoadRows(){_list.Items.Clear();foreach(var row in QuarantineStore.Read().OrderByDescending(x=>x.QuarantinedAt)){var item=new ListViewItem(row.QuarantinedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm"));item.SubItems.Add(row.OriginalPath);item.SubItems.Add(row.Sha256.Length>24?row.Sha256[..24]+"…":row.Sha256);item.SubItems.Add(row.OriginalSize>0?$"{row.OriginalSize/1024d/1024d:N1} MB":"-");item.SubItems.Add(row.Reason);item.Tag=row;_list.Items.Add(item);}}
    async Task RestoreSelected(){if(_list.SelectedItems.Count==0)return;var row=(QuarantineRecord)_list.SelectedItems[0].Tag!;if(MessageBox.Show("Restaurar puede volver a exponer una amenaza. ¿Continuar?","GivenX Shield",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;try{var path=await QuarantineStore.RestoreAsync(row.Id);MessageBox.Show("Restaurado en:\n"+path,"GivenX Shield");LoadRows();}catch(Exception ex){MessageBox.Show(ex.Message,"Error",MessageBoxButtons.OK,MessageBoxIcon.Error);}}
    async Task AllowFile(){using var dialog=new OpenFileDialog{Title="Selecciona un archivo confiable"};if(dialog.ShowDialog()!=DialogResult.OK)return;await using var stream=File.OpenRead(dialog.FileName);var hash=Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();AllowListStore.Add(hash);MessageBox.Show("Hash agregado a la lista segura. Si el archivo cambia, deberá autorizarse nuevamente.","GivenX Shield");}
    async Task QuarantineFile(){using var dialog=new OpenFileDialog{Title="Selecciona el archivo que deseas aislar"};if(dialog.ShowDialog()!=DialogResult.OK)return;if(MessageBox.Show("El archivo se cifrará y dejará de estar disponible en su ubicación original. ¿Continuar?","GivenX Shield",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;try{await QuarantineStore.QuarantineAsync(dialog.FileName,"Aislamiento manual confirmado por el usuario");LoadRows();}catch(Exception ex){MessageBox.Show(ex.Message,"No se pudo aislar",MessageBoxButtons.OK,MessageBoxIcon.Error);}}
    async Task BlockNetwork(){using var dialog=new OpenFileDialog{Title="Selecciona el ejecutable que no podrá conectarse",Filter="Ejecutables (*.exe)|*.exe"};if(dialog.ShowDialog()!=DialogResult.OK)return;if(MessageBox.Show("GivenX creará una regla de salida en Windows Firewall para este programa. ¿Continuar?","GivenX Shield",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;try{var row=await FirewallResponse.BlockAsync(dialog.FileName);MessageBox.Show("Red bloqueada. Regla reversible:\n"+row.RuleName,"GivenX Shield");}catch(Exception ex){MessageBox.Show(ex.Message,"No se pudo bloquear",MessageBoxButtons.OK,MessageBoxIcon.Error);}}
}

using GivenX.Shared;

namespace GivenX.UI;

public sealed class NetworkBlocksForm:Form
{
    readonly ListView _blocks=List(),_history=List();
    public NetworkBlocksForm()
    {
        Text="GivenX Shield | Bloqueos e historial de respuesta";Size=new(1000,600);StartPosition=FormStartPosition.CenterParent;BackColor=Color.FromArgb(7,12,20);ForeColor=Color.White;Font=new("Segoe UI",10);
        _blocks.Columns.Add("Fecha",145);_blocks.Columns.Add("Tipo",90);_blocks.Columns.Add("Objetivo",380);_blocks.Columns.Add("Regla reversible",300);
        _history.Columns.Add("Fecha",145);_history.Columns.Add("Acción",180);_history.Columns.Add("Objetivo",260);_history.Columns.Add("Resultado",110);_history.Columns.Add("Detalle",360);
        var tabs=new TabControl{Dock=DockStyle.Fill};tabs.TabPages.Add(Page("BLOQUEOS ACTIVOS",_blocks));tabs.TabPages.Add(Page("HISTORIAL DE RESPUESTA",_history));
        var bar=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=60,Padding=new(14,11,0,0),BackColor=Color.FromArgb(14,23,36)};var remove=Button("RETIRAR BLOQUEO",170);remove.Click+=async(_,_)=>await Remove();bar.Controls.Add(remove);var refresh=Button("ACTUALIZAR",130);refresh.Click+=(_,_)=>LoadRows();bar.Controls.Add(refresh);
        Controls.Add(tabs);Controls.Add(bar);bar.BringToFront();LoadRows();
    }
    static ListView List()=>new(){Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,BackColor=Color.FromArgb(9,16,26),ForeColor=Color.White,BorderStyle=BorderStyle.None};
    static TabPage Page(string title,Control content){var page=new TabPage(title){BackColor=Color.FromArgb(7,12,20),ForeColor=Color.White,Padding=new(10)};page.Controls.Add(content);return page;}
    static Button Button(string text,int width)=>new(){Text=text,Width=width,Height=34,FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(25,39,58),ForeColor=Color.White,FlatAppearance={BorderColor=Color.FromArgb(255,116,22)}};
    void LoadRows()
    {
        _blocks.Items.Clear();foreach(var row in FirewallResponse.Read().OrderByDescending(x=>x.CreatedAt)){var target=string.IsNullOrWhiteSpace(row.Target)?row.ProgramPath:row.Target;var item=new ListViewItem(row.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm"));item.SubItems.Add(row.Kind??"Programa");item.SubItems.Add(target);item.SubItems.Add(row.RuleName);item.Tag=row;_blocks.Items.Add(item);}
        _history.Items.Clear();foreach(var row in ResponseActionStore.Read()){var item=new ListViewItem(row.Time.LocalDateTime.ToString("yyyy-MM-dd HH:mm"));item.SubItems.Add(row.Action);item.SubItems.Add(row.Target);item.SubItems.Add(row.Outcome);item.SubItems.Add(row.Details);item.ForeColor=row.Outcome=="ERROR"?Color.FromArgb(255,73,91):row.Outcome=="COMPLETADO"?Color.FromArgb(66,226,151):Color.FromArgb(255,190,70);_history.Items.Add(item);}
    }
    async Task Remove(){if(_blocks.SelectedItems.Count==0)return;var row=(NetworkBlock)_blocks.SelectedItems[0].Tag!;var target=string.IsNullOrWhiteSpace(row.Target)?row.ProgramPath:row.Target;if(MessageBox.Show(this,$"¿Retirar el bloqueo de {target}?","GivenX Shield",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;try{await FirewallResponse.UnblockAsync(row.RuleName);LoadRows();}catch(Exception ex){MessageBox.Show(this,ex.Message,"Error",MessageBoxButtons.OK,MessageBoxIcon.Error);}}
}

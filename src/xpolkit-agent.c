#include <grp.h>
#include <pwd.h>
#include <gtk/gtk.h>

#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <polkit/polkit.h>

G_BEGIN_DECLS

#define XPOLKIT_LISTENER_GET_TYPE (xpolkit_listener_get_type())
#define XPOLKIT_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), XPOLKIT_LISTENER_GET_TYPE, XPolkitListener))

typedef struct _XPolkitListener  XPolkitListener;
typedef struct _XPolkitListenerClass XPolkitListenerClass;

struct _XPolkitListener {
  PolkitAgentListener parent;
};

struct _XPolkitListenerClass {
  PolkitAgentListenerClass parent_class;
};

GType xpolkit_listener_get_type(void);
PolkitAgentListener* xpolkit_listener_new(void);

G_END_DECLS



G_DEFINE_TYPE(XPolkitListener, xpolkit_listener, POLKIT_AGENT_TYPE_LISTENER);

typedef struct _AuthDlgData AuthDlgData;
struct _AuthDlgData {
	PolkitAgentSession *session;
	gchar *action_id;
	gchar *cookie;
	GCancellable* cancellable;
	GTask* task;
	GtkWidget *auth_dlg;
	GtkWidget *entry_label;
	GtkWidget *entry;
	GtkWidget *id_combo;
	GtkWidget *status;
};

static void on_cancelled(GCancellable* cancellable, AuthDlgData* d);
static void on_id_combo_user_changed(GtkComboBox *box, AuthDlgData *d);

static void auth_dlg_data_free(AuthDlgData *d)
{
	gtk_widget_destroy(d->auth_dlg);
	g_signal_handlers_disconnect_by_func(d->cancellable, on_cancelled, d);

	g_object_unref(d->task);
	g_object_unref(d->session);
	g_free(d->action_id);
	g_free(d->cookie);
	g_slice_free(AuthDlgData, d);
}

static void on_cancelled(GCancellable *cancellable, AuthDlgData *d)
{
	if (d->session)
		polkit_agent_session_cancel(d->session);
	else
		auth_dlg_data_free(d);
}

static void on_auth_dlg_response(GtkDialog *dlg, int response, AuthDlgData *d)
{
  if(response == GTK_RESPONSE_OK && strlen(gtk_entry_get_text(GTK_ENTRY(d->entry))) == 0) {
	  gtk_widget_set_sensitive(d->auth_dlg, TRUE);
	  gtk_label_set_text(GTK_LABEL(d->status), "Failed. Empty password!");
	  g_object_unref(d->session);
	  d->session = NULL;
	  gtk_entry_set_text(GTK_ENTRY(d->entry), "");
	  gtk_widget_grab_focus(d->entry);
	  on_id_combo_user_changed(GTK_COMBO_BOX(d->id_combo), d);
    return;
  }

	if (response == GTK_RESPONSE_OK) {
		const char *txt = gtk_entry_get_text(GTK_ENTRY(d->entry));
		polkit_agent_session_response(d->session, txt);
		gtk_widget_set_sensitive(d->auth_dlg, FALSE);
	} else
		g_cancellable_cancel(d->cancellable);
}

static void on_session_completed(PolkitAgentSession* session,
				 gboolean authorized, AuthDlgData* d)
{
	gtk_widget_set_sensitive(d->auth_dlg, TRUE);
	if (authorized || g_cancellable_is_cancelled(d->cancellable)) {
		gtk_label_set_text(GTK_LABEL(d->status), NULL);
		g_task_return_pointer(d->task, NULL, NULL);
		auth_dlg_data_free(d);
		return;
	}
	gtk_label_set_text(GTK_LABEL(d->status), "Failed. Wrong password?");
	g_object_unref(d->session);
	d->session = NULL;
	gtk_entry_set_text(GTK_ENTRY(d->entry), "");
	gtk_widget_grab_focus(d->entry);
	on_id_combo_user_changed(GTK_COMBO_BOX(d->id_combo), d);
}

static void on_session_request(PolkitAgentSession* session, gchar *req,
			       gboolean visibility, AuthDlgData *d)
{
	gtk_label_set_text(GTK_LABEL(d->entry_label), req);
	gtk_entry_set_visibility(GTK_ENTRY(d->entry), visibility);
}

static void on_id_combo_user_changed(GtkComboBox *combo, AuthDlgData *d)
{
	GtkTreeIter iter;
	GtkTreeModel *model = gtk_combo_box_get_model(combo);
	PolkitIdentity *id;

	if (!gtk_combo_box_get_active_iter(combo, &iter))
		return;

	gtk_tree_model_get(model, &iter, 1, &id, -1);
	if (d->session) {
		g_signal_handlers_disconnect_matched(d->session,
						     G_SIGNAL_MATCH_DATA,
						     0, 0, NULL, NULL, d);
		polkit_agent_session_cancel(d->session);
		g_object_unref(d->session);
	}

	d->session = polkit_agent_session_new(id, d->cookie);
	g_object_unref(id);
	g_signal_connect(d->session, "completed",
			 G_CALLBACK(on_session_completed), d);
	g_signal_connect(d->session, "request",
			 G_CALLBACK(on_session_request), d);
	polkit_agent_session_initiate(d->session);
}

static void on_entry_activate(GtkWidget *entry, AuthDlgData *d)
{
	gtk_dialog_response(GTK_DIALOG(d->auth_dlg), GTK_RESPONSE_OK);
}

static void add_identities(GtkComboBox *combo, GList *identities)
{
	GList *p;
	GtkCellRenderer *column;
	GtkListStore *store;

	store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_OBJECT);
	for (p = identities; p != NULL; p = p->next) {
		gchar *str = NULL;
		PolkitIdentity *id = (PolkitIdentity *)p->data;
		if(POLKIT_IS_UNIX_USER(id)) {
			uid_t uid = polkit_unix_user_get_uid(POLKIT_UNIX_USER(id));
			struct passwd *pwd = getpwuid(uid);
			str = g_strdup(pwd->pw_name);
		} else if(POLKIT_IS_UNIX_GROUP(id)) {
			gid_t gid = polkit_unix_group_get_gid(POLKIT_UNIX_GROUP(id));
			struct group *grp = getgrgid(gid);
			str = g_strdup_printf("Group: %s", grp->gr_name);
		} else {
			str = polkit_identity_to_string(id);
		}
		gtk_list_store_insert_with_values(store, NULL, -1,
						  0, str,
						  1, id,
						  -1);
		g_free(str);
	}
	gtk_combo_box_set_model(combo, GTK_TREE_MODEL(store));
	g_object_unref(store);

	column = gtk_cell_renderer_text_new();
	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo), column, TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo), column,
				       "text", 0, NULL);
}

static GtkWidget *grid2x2(GtkWidget *top_left, GtkWidget *top_right,
			 GtkWidget *bottom_left, GtkWidget *bottom_right)
{
	GtkWidget *table = gtk_grid_new();
	gtk_grid_attach(GTK_GRID(table), top_left, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(table), top_right, 1, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(table), bottom_left, 0, 1, 1, 1);
	gtk_grid_attach(GTK_GRID(table), bottom_right, 1, 1, 1, 1);
	gtk_widget_show(table);
	return table;
}

static void initiate_authentication(PolkitAgentListener  *listener,
				    const gchar          *action_id,
				    const gchar          *message,
				    const gchar          *icon_name,
				    PolkitDetails        *details,
				    const gchar          *cookie,
				    GList                *identities,
				    GCancellable         *cancellable,
				    GAsyncReadyCallback   callback,
				    gpointer              user_data)
{
	GtkWidget *content;
	GtkWidget *combo_label;
	GtkWidget *grid;
	AuthDlgData *d = g_slice_new0(AuthDlgData);

	d->task = g_task_new(listener, cancellable, callback, user_data);
	d->cancellable = cancellable;
	d->action_id = g_strdup(action_id);
	d->cookie = g_strdup(cookie);
	d->auth_dlg = gtk_dialog_new_with_buttons("Authenticate", NULL,
            GTK_DIALOG_MODAL,
			"Cancel", GTK_RESPONSE_CANCEL,
			"Authenticate", GTK_RESPONSE_OK,
			NULL);

  gtk_window_set_keep_above(GTK_WINDOW(d->auth_dlg), TRUE);
  gtk_window_set_icon_name (GTK_WINDOW(d->auth_dlg), "dialog-password");

  gtk_container_set_border_width (GTK_CONTAINER (d->auth_dlg), 5);

	content = gtk_dialog_get_content_area(GTK_DIALOG(d->auth_dlg));

  gtk_box_set_spacing (GTK_BOX (content), 2); /* 2 * 5 + 2 = 12 */
  gtk_window_set_resizable (GTK_WINDOW(d->auth_dlg), FALSE);

	combo_label = gtk_label_new("Identity:");
	gtk_widget_show(combo_label);

	d->id_combo = gtk_combo_box_new();
	add_identities(GTK_COMBO_BOX(d->id_combo), identities);
	g_signal_connect(d->id_combo, "changed",
			 G_CALLBACK(on_id_combo_user_changed), d);
	gtk_combo_box_set_active(GTK_COMBO_BOX(d->id_combo), 0);
	gtk_widget_show(d->id_combo);

	d->entry_label = gtk_label_new(NULL);
	gtk_widget_show(d->entry_label);

	d->entry = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(d->entry), FALSE);
	gtk_widget_show(d->entry);
	g_signal_connect (d->entry, "activate", G_CALLBACK(on_entry_activate), d);

	grid = grid2x2(combo_label, d->id_combo, d->entry_label, d->entry);
	gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);

	d->status = gtk_label_new(NULL);
	gtk_box_pack_start(GTK_BOX(content), d->status, TRUE, TRUE, 0);
	gtk_widget_show(d->status);

	g_signal_connect(cancellable, "cancelled", G_CALLBACK(on_cancelled), d);
	g_signal_connect(d->auth_dlg, "response",
			 G_CALLBACK(on_auth_dlg_response), d);

	gtk_widget_grab_focus(d->entry);
	gtk_window_present(GTK_WINDOW(d->auth_dlg));
}

static gboolean initiate_authentication_finish(PolkitAgentListener *listener,
				 GAsyncResult *res, GError **error)
{
  gboolean has_error = g_task_had_error(G_TASK(res));
  g_task_propagate_pointer (G_TASK(res), error);
	return !has_error;
}

static void xpolkit_listener_finalize(GObject *object)
{
	XPolkitListener *self;

	g_return_if_fail(object != NULL);

	self = XPOLKIT_LISTENER(object);

	G_OBJECT_CLASS(xpolkit_listener_parent_class)->finalize(object);
}

static void xpolkit_listener_class_init(XPolkitListenerClass *klass)
{
	GObjectClass *g_object_class;
	PolkitAgentListenerClass* pkal_class;
	g_object_class = G_OBJECT_CLASS(klass);
	g_object_class->finalize = xpolkit_listener_finalize;

	pkal_class = POLKIT_AGENT_LISTENER_CLASS(klass);
	pkal_class->initiate_authentication = initiate_authentication;
	pkal_class->initiate_authentication_finish = initiate_authentication_finish;
}

static void xpolkit_listener_init(XPolkitListener *self)
{
}

PolkitAgentListener* xpolkit_listener_new(void)
{
	return g_object_new(XPOLKIT_LISTENER_GET_TYPE, NULL);
}



int main(int argc, char *argv[])
{
	PolkitAgentListener *listener;
	PolkitSubject* session;
	GError* err = NULL;
	int rc = 0;

	gtk_init(&argc, &argv);

	listener = xpolkit_listener_new();
	session = polkit_unix_session_new_for_process_sync(getpid(), NULL, NULL);

	if(!polkit_agent_listener_register(listener,
					   POLKIT_AGENT_REGISTER_FLAGS_NONE,
					   session, NULL, NULL, &err)) {
		rc = 1;
	} else {
		gtk_main();
	}

	g_object_unref(listener);
	g_object_unref(session);
	return rc;
}

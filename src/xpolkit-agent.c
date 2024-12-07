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
  GtkWidget *passwd_label;
  GtkWidget *passwd_entry;
  GtkWidget *id_dropdown;
  GtkWidget *status_label;
};

static void on_cancelled(GCancellable* cancellable, AuthDlgData* d);

static void on_user_changed (GtkDropDown *dropdown, GParamSpec *pspec, gpointer data);


static void auth_dlg_data_free(AuthDlgData *d)
{
  gtk_window_destroy(GTK_WINDOW(d->auth_dlg));
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


static void cancel_btn_click_cb(GtkWidget *widget, AuthDlgData *d)
{
  g_cancellable_cancel(d->cancellable);
}

static void ok_btn_click_cb(GtkWidget *widget, AuthDlgData *d)
{
  if(gtk_widget_is_visible(d->passwd_entry) == FALSE) {
    return;
  }

  const char *password = gtk_editable_get_text(GTK_EDITABLE(d->passwd_entry));
  if(strlen(password) == 0) {
    gtk_label_set_text(GTK_LABEL(d->status_label), "Failed. Empty password.");
    return;
  }
  polkit_agent_session_response(d->session, password);
  gtk_widget_set_sensitive(d->auth_dlg, FALSE);
}

static void on_session_completed(PolkitAgentSession* session,
         gboolean authorized, AuthDlgData* d)
{
  gtk_widget_set_sensitive(d->auth_dlg, TRUE);

  // hide password label and entry,
  // show it when request again.
  gtk_widget_set_visible(d->passwd_label, FALSE);
  gtk_widget_set_visible(d->passwd_entry, FALSE);

  if (authorized  || g_cancellable_is_cancelled(d->cancellable)) {
    gtk_label_set_text(GTK_LABEL(d->status_label), NULL);
    g_task_return_pointer(d->task, NULL, NULL);
    auth_dlg_data_free(d);
    return;
  }

  g_object_unref(d->session);
  d->session = NULL;
  gtk_label_set_text(GTK_LABEL(d->status_label), "");
  gtk_editable_set_text(GTK_EDITABLE(d->passwd_entry), "");
  gtk_widget_grab_focus(d->passwd_entry);
  on_user_changed(GTK_DROP_DOWN(d->id_dropdown), NULL, d);
}

static void on_session_request(PolkitAgentSession* session, gchar *req,
             gboolean echo_on, AuthDlgData *d)
{
  // show passwd_label/entry only when requested.
  // if fprint enabled, after failed 3 times,
  // It will fallback to password auth.
  gtk_widget_set_visible(d->passwd_label, TRUE);
  gtk_widget_set_visible(d->passwd_entry, TRUE);

  // clean status label
  gtk_label_set_text(GTK_LABEL(d->status_label), "");

  gtk_label_set_text(GTK_LABEL(d->passwd_label), req);
  gtk_entry_set_visibility(GTK_ENTRY(d->passwd_entry), echo_on);
}


//reuse status label
static void on_show_session_msg(PolkitAgentSession* session, gchar* text, AuthDlgData* d)
{
  gtk_label_set_text(GTK_LABEL(d->status_label),text);
}


static void on_user_changed (GtkDropDown *dropdown,
                  GParamSpec *pspec,
                  gpointer data)
{

  GListModel *model;
  guint selected;
  PolkitIdentity *id;

  AuthDlgData *d = data;
  
  // hide password label and entry,
  // show it when request again.
  gtk_widget_set_visible(d->passwd_label, FALSE);
  gtk_widget_set_visible(d->passwd_entry, FALSE);

  model = gtk_drop_down_get_model (dropdown);
  selected = gtk_drop_down_get_selected (dropdown);
  id = g_list_model_get_item (model, selected);

  if(!id)
    return;

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
  g_signal_connect(d->session, "show-error", G_CALLBACK(on_show_session_msg), d);
  g_signal_connect(d->session, "show-info", G_CALLBACK(on_show_session_msg), d);
  polkit_agent_session_initiate(d->session);
}

static gchar *polkitid_to_string(PolkitIdentity *id) {
  if(POLKIT_IS_UNIX_USER(id)) {
    uid_t uid = polkit_unix_user_get_uid(POLKIT_UNIX_USER(id));
    struct passwd *pwd = getpwuid(uid);
    return g_strdup(pwd->pw_name);
  } else if(POLKIT_IS_UNIX_GROUP(id)) {
    gid_t gid = polkit_unix_group_get_gid(POLKIT_UNIX_GROUP(id));
    struct group *grp = getgrgid(gid);
    return g_strdup_printf("Group: %s", grp->gr_name);
  } else {
    return polkit_identity_to_string(id);
  }
}

static gboolean
key_pressed_cb (GtkEventControllerKey *event_controller,
                guint                  keyval,
                guint                  keycode,
                GdkModifierType        state,
                AuthDlgData* d)
{
  if(keyval == GDK_KEY_Escape)
    g_cancellable_cancel(d->cancellable);
  return TRUE;
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
  GtkWidget *combo_label;
  AuthDlgData *d = g_slice_new0(AuthDlgData);

  d->task = g_task_new(listener, cancellable, callback, user_data);
  d->cancellable = cancellable;
  d->action_id = g_strdup(action_id);
  d->cookie = g_strdup(cookie);

  d->auth_dlg = gtk_window_new();
  //gtk_widget_set_size_request(d->auth_dlg, 40,30);
  //gtk_window_set_default_size(GTK_WINDOW(d->auth_dlg), 400, -1);
  gtk_window_set_title(GTK_WINDOW(d->auth_dlg), "Authenticate");
  gtk_window_set_modal(GTK_WINDOW(d->auth_dlg), TRUE);
  gtk_window_set_icon_name (GTK_WINDOW(d->auth_dlg), "dialog-password");
  gtk_window_set_resizable (GTK_WINDOW(d->auth_dlg), FALSE);


  // handle esc key
  GtkEventController *event_controller; 
  event_controller = gtk_event_controller_key_new ();
  g_signal_connect(event_controller, "key-pressed", G_CALLBACK (key_pressed_cb), d);
  gtk_widget_add_controller (GTK_WIDGET (d->auth_dlg), event_controller);

  GtkWidget *grid = gtk_grid_new();
  gtk_window_set_child(GTK_WINDOW(d->auth_dlg), grid);

  GtkWidget *message_label = gtk_label_new(message);
  //gtk_label_set_wrap(GTK_LABEL(message_label), TRUE);
  gtk_grid_attach(GTK_GRID(grid), message_label, 0, 0, 2, 1); 

  combo_label = gtk_label_new("Identity:");
  gtk_grid_attach(GTK_GRID(grid), combo_label, 0,1,1,1);
  
  
  GListStore *store = g_list_store_new(POLKIT_TYPE_IDENTITY);
  GList *p;
  for (p = identities; p != NULL; p = p->next) {
    PolkitIdentity *id = (PolkitIdentity *)p->data;
    g_list_store_append(store, id);
  }

  GtkExpression *expression;
  expression = gtk_cclosure_expression_new (G_TYPE_STRING, NULL,
                                            0, NULL,
                                            (GCallback)polkitid_to_string,
                                            NULL, NULL);


  d->id_dropdown = gtk_drop_down_new(G_LIST_MODEL(store),expression);
  gtk_grid_attach(GTK_GRID(grid), d->id_dropdown, 1,1,1,1);

  g_signal_connect (d->id_dropdown, "notify::selected", G_CALLBACK (on_user_changed), d);

  gtk_drop_down_set_selected(GTK_DROP_DOWN(d->id_dropdown), 0);  



  d->passwd_label = gtk_label_new(NULL);
  gtk_grid_attach(GTK_GRID(grid), d->passwd_label, 0,2,1,1);

  d->passwd_entry = gtk_entry_new();
  gtk_grid_attach(GTK_GRID(grid), d->passwd_entry, 1,2,1,1);

  gtk_entry_set_activates_default(GTK_ENTRY(d->passwd_entry), TRUE);

  gtk_entry_set_visibility(GTK_ENTRY(d->passwd_entry), FALSE);


  //hide passwd_label/entry when init
  //If password requested, it will show in on_session_request function.
  gtk_widget_set_visible(d->passwd_label, FALSE);
  gtk_widget_set_visible(d->passwd_entry, FALSE);

  g_signal_connect(d->passwd_entry, "activate", G_CALLBACK(ok_btn_click_cb), d);

  d->status_label = gtk_label_new(NULL);
  gtk_grid_attach(GTK_GRID(grid), d->status_label, 0,3,2,1);
 

  GtkWidget *cancel_button = gtk_button_new_with_label("Cancel");
  GtkWidget *ok_button = gtk_button_new_with_label("OK");

  GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
  gtk_box_set_homogeneous(GTK_BOX(box), TRUE);

  gtk_box_append(GTK_BOX(box), cancel_button);
  gtk_box_append(GTK_BOX(box), ok_button);
  gtk_grid_attach(GTK_GRID(grid), box, 0,4,2,1);

  g_signal_connect(cancel_button, "clicked", G_CALLBACK(cancel_btn_click_cb), d);
  g_signal_connect(ok_button, "clicked", G_CALLBACK(ok_btn_click_cb), d);
  
  g_signal_connect(cancellable, "cancelled", G_CALLBACK(on_cancelled), d);

  gtk_widget_grab_focus(d->passwd_entry);

  gtk_window_present(GTK_WINDOW(d->auth_dlg));
  
  on_user_changed(GTK_DROP_DOWN(d->id_dropdown), NULL, d );
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
  GMainLoop *mainloop = g_main_loop_new(NULL, FALSE);
  PolkitAgentListener *listener;

  PolkitSubject* session;
  GError* err = NULL;

  gtk_init();

  listener = xpolkit_listener_new();
  session = polkit_unix_session_new_for_process_sync(getpid(), NULL, NULL);

  if(!polkit_agent_listener_register(listener,
             POLKIT_AGENT_REGISTER_FLAGS_NONE,
             session, NULL, NULL, &err)) {
    fprintf(stderr, "Register polkit listener error.");
    exit(1);
  }

  g_main_loop_run(mainloop);

  g_object_unref(listener);
  g_object_unref(session);
}

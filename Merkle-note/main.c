
//code by amiriiw 

#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 64
#define KEY_SIZE 32
#define IV_SIZE 16

GtkWidget *text_view;
GtkWidget *window;

unsigned char* calculateMerkleRootFromText(const char *text) {
    size_t size = strlen(text);
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        perror("Memory allocation failed");
        exit(1);
    }
    SHA256((unsigned char*)text, size, hash);
    return hash;
}

void appendMerkleRootToFile(const unsigned char* merkleRoot) {
    FILE* file = fopen("pass.txt", "a");
    if (!file) {
        perror("Error opening pass.txt for writing");
        exit(1);
    }

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(file, "%02x", merkleRoot[i]);
    }
    fprintf(file, "\n");
    fclose(file);
}

void encryptTextToFile(const char *filename, const char *text, const unsigned char *key) {
    FILE *out = fopen(filename, "wb");
    if (!out) {
        perror("Error opening file for encryption");
        exit(1);
    }

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        perror("Error generating IV");
        fclose(out);
        exit(1);
    }

    fwrite(iv, 1, IV_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int cipherLen;

    int textLen = strlen(text);
    int offset = 0;

    while (textLen > 0) {
        int chunk = textLen > BLOCK_SIZE ? BLOCK_SIZE : textLen;
        memcpy(buffer, text + offset, chunk);
        EVP_EncryptUpdate(ctx, ciphertext, &cipherLen, buffer, chunk);
        fwrite(ciphertext, 1, cipherLen, out);
        textLen -= chunk;
        offset += chunk;
    }

    EVP_EncryptFinal_ex(ctx, ciphertext, &cipherLen);
    fwrite(ciphertext, 1, cipherLen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(out);
}

char* decryptTextFromFile(const char *filename, const unsigned char *key) {
    FILE *in = fopen(filename, "rb");
    if (!in) {
        perror("Error opening file for decryption");
        return NULL;
    }

    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        perror("Error reading IV");
        fclose(in);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    char *text = malloc(1024);
    size_t textSize = 0;

    unsigned char buffer[BLOCK_SIZE];
    unsigned char plaintext[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int plainLen, bytesRead;

    while ((bytesRead = fread(buffer, 1, BLOCK_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, plaintext, &plainLen, buffer, bytesRead);
        memcpy(text + textSize, plaintext, plainLen);
        textSize += plainLen;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext, &plainLen) != 1) {
        perror("Decryption failed");
        fclose(in);
        free(text);
        return NULL;
    }

    memcpy(text + textSize, plaintext, plainLen);
    textSize += plainLen;
    text[textSize] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);

    return text;
}

void on_save_button_clicked(GtkWidget *widget, gpointer user_data) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    char *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    unsigned char *merkleRoot = calculateMerkleRootFromText(text);

    appendMerkleRootToFile(merkleRoot);

    GtkWidget *dialog = gtk_file_chooser_dialog_new("Save File", GTK_WINDOW(window),
                                                    GTK_FILE_CHOOSER_ACTION_SAVE,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Save", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        encryptTextToFile(filename, text, merkleRoot);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);

    free(merkleRoot);
    g_free(text);
}

void on_open_button_clicked(GtkWidget *widget, gpointer user_data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Open File", GTK_WINDOW(window),
                                                    GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Open", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

        GtkWidget *keyDialog = gtk_dialog_new_with_buttons("Enter Merkle Root",
                                                           GTK_WINDOW(window),
                                                           GTK_DIALOG_MODAL,
                                                           "_OK", GTK_RESPONSE_ACCEPT,
                                                           "_Cancel", GTK_RESPONSE_CANCEL,
                                                           NULL);

        GtkWidget *contentArea = gtk_dialog_get_content_area(GTK_DIALOG(keyDialog));
        GtkWidget *entry = gtk_entry_new();
        gtk_entry_set_max_length(GTK_ENTRY(entry), SHA256_DIGEST_LENGTH * 2);
        gtk_container_add(GTK_CONTAINER(contentArea), entry);
        gtk_widget_show(entry);

        GtkWidget *ok_button = gtk_dialog_get_widget_for_response(GTK_DIALOG(keyDialog), GTK_RESPONSE_ACCEPT);
        GtkWidget *cancel_button = gtk_dialog_get_widget_for_response(GTK_DIALOG(keyDialog), GTK_RESPONSE_CANCEL);

        gtk_widget_set_size_request(ok_button, 255, -1);
        gtk_widget_set_size_request(cancel_button, 255, -1);

        if (gtk_dialog_run(GTK_DIALOG(keyDialog)) == GTK_RESPONSE_ACCEPT) {
            const char *keyHex = gtk_entry_get_text(GTK_ENTRY(entry));
            unsigned char key[KEY_SIZE];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                sscanf(keyHex + (i * 2), "%2hhx", &key[i]);
            }

            char *text = decryptTextFromFile(filename, key);
            if (text) {
                GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
                gtk_text_buffer_set_text(buffer, text, -1);
                free(text);
            } else {
                GtkWidget *errorDialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                                                GTK_DIALOG_MODAL,
                                                                GTK_MESSAGE_ERROR,
                                                                GTK_BUTTONS_CLOSE,
                                                                "Decryption failed!");
                gtk_dialog_run(GTK_DIALOG(errorDialog));
                gtk_widget_destroy(errorDialog);
            }
        }

        gtk_widget_destroy(keyDialog);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}


int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Merkle Notepad");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    GtkWidget *save_button = gtk_button_new_with_label("Save");
    g_signal_connect(save_button, "clicked", G_CALLBACK(on_save_button_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hbox), save_button, FALSE, FALSE, 0);

    GtkWidget *open_button = gtk_button_new_with_label("Open");
    g_signal_connect(open_button, "clicked", G_CALLBACK(on_open_button_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hbox), open_button, FALSE, FALSE, 0);

    text_view = gtk_text_view_new();
    gtk_box_pack_start(GTK_BOX(vbox), text_view, TRUE, TRUE, 0);

    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(text_view), 10);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(text_view), 10);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(text_view), 15);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(text_view), 15);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

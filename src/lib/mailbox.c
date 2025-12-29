// #include "mailbox.h"
// #include <stdlib.h>
// #include <string.h>
// #include <time.h>

// Mailbox* create_mailbox(const char* name) {
//     Mailbox* mailbox = malloc(sizeof(Mailbox));
//     if (!mailbox) return NULL;
    
//     mailbox->name = strdup(name);
//     mailbox->messages = NULL;
//     mailbox->message_count = 0;
//     mailbox->next_uid = 1;
    
//     return mailbox;
// }

// void destroy_mailbox(Mailbox* mailbox) {
//     if (!mailbox) return;
    
//     free(mailbox->name);
    
//     for (int i = 0; i < mailbox->message_count; i++) {
//         EmailMessage* msg = mailbox->messages[i];
//         free(msg->from);
//         free(msg->to);
//         free(msg->subject);
//         free(msg->date);
//         free(msg->body);
//         free(msg);
//     }
    
//     free(mailbox->messages);
//     free(mailbox);
// }

// EmailMessage* create_email(const char* from, const char* to, 
//                           const char* subject, const char* body) {
//     EmailMessage* email = malloc(sizeof(EmailMessage));
//     if (!email) return NULL;
    
//     email->from = strdup(from);
//     email->to = strdup(to);
//     email->subject = strdup(subject);
//     email->body = strdup(body);
//     email->flags = 0; // Unread by default
//     email->size = strlen(body);
    
//     // Set current date
//     time_t now = time(NULL);
//     email->date = malloc(64);
//     strftime(email->date, 64, "%a, %d %b %Y %H:%M:%S %z", localtime(&now));
    
//     return email;
// }

// void add_email_to_mailbox(Mailbox* mailbox, EmailMessage* email) {
//     if (!mailbox || !email) return;
    
//     email->uid = mailbox->next_uid++;
    
//     mailbox->messages = realloc(mailbox->messages, 
//                                sizeof(EmailMessage*) * (mailbox->message_count + 1));
//     mailbox->messages[mailbox->message_count] = email;
//     mailbox->message_count++;
// }

// EmailMessage* get_email_by_uid(Mailbox* mailbox, int uid) {
//     if (!mailbox) return NULL;
    
//     for (int i = 0; i < mailbox->message_count; i++) {
//         if (mailbox->messages[i]->uid == uid) {
//             return mailbox->messages[i];
//         }
//     }
    
//     return NULL;
// }

// int get_email_count(Mailbox* mailbox) {
//     return mailbox ? mailbox->message_count : 0;
// }

// int get_unread_count(Mailbox* mailbox) {
//     if (!mailbox) return 0;
    
//     int count = 0;
//     for (int i = 0; i < mailbox->message_count; i++) {
//         if ((mailbox->messages[i]->flags & 1) == 0) { // Check if not seen
//             count++;
//         }
//     }
    
//     return count;
// }
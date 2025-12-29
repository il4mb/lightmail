#ifndef MAILBOX_H
#define MAILBOX_H

// typedef struct {
//     int uid;
//     char* from;
//     char* to;
//     char* subject;
//     char* date;
//     char* body;
//     int size;
//     int flags; // 1=Seen, 2=Answered, 4=Flagged, 8=Deleted, 16=Draft
// } EmailMessage;

// typedef struct {
//     char* name;
//     EmailMessage** messages;
//     int message_count;
//     int next_uid;
// } Mailbox;

// // Mailbox functions
// Mailbox* create_mailbox(const char* name);
// void destroy_mailbox(Mailbox* mailbox);
// EmailMessage* create_email(const char* from, const char* to, 
//                           const char* subject, const char* body);
// void add_email_to_mailbox(Mailbox* mailbox, EmailMessage* email);
// EmailMessage* get_email_by_uid(Mailbox* mailbox, int uid);
// int get_email_count(Mailbox* mailbox);
// int get_unread_count(Mailbox* mailbox);

#endif
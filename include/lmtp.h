#ifndef LMTP_H
#define LMTP_H

/**
 * @brief Starts the LMTP server.
 *
 * This function initializes the LMTP listener socket and enters the main accept loop
 * to handle incoming connections from the local MTA (e.g., Postfix).
 *
 * @return 0 on successful shutdown, -1 on error.
 */
int start_lmtp(void);

#endif // LMTP_H

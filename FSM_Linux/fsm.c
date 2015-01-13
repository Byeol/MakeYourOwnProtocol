//
// fsm.c
// FSM sample code
//
// Created by Minsuk Lee, 2014.11.1.
// Edited by Jaewon Seo, 2015.1.10.
// Copyright (c) 2014. Minsuk Lee & Jaewon All rights reserved.
// see LICENSE

#include "util.h"

#define CONNECT_TIMEOUT 3
#define SEND_TIMEOUT    5

#define SEND_BUFFER_SIZE 1

#define NUM_STATE   5
#define NUM_EVENT   8

#define F_DATA 0x0
#define F_ACK 0x1
#define F_SYN 0x2
#define F_FIN 0x4

// States
enum proto_state { LISTEN = 0, SYN_SENT = 1, SYN_RECEIVED = 2, ESTABLISHED = 3, SENDING = 4};

// Events
enum proto_event { RCV_SYN = 0, RCV_FIN = 1, RCV_ACK = 2, RCV_DATA = 3,
                   CONNECT = 4, CLOSE = 5,   SEND = 6,    TIMEOUT = 7 };

char *st_name[] =  { "LISTEN", "SYN-SENT", "SYN-RECEIVED", "ESTABLISHED", "SENDING" };
char *ev_name[] =  { "RCV_SYN", "RCV_FIN", "RCV_ACK", "RCV_DATA",
                     "CONNECT", "CLOSE",   "SEND",    "TIMEOUT"   };

struct state_action {           // Protocol FSM Structure
    void (* action)(void *p);
    enum proto_state next_state;
};

#define MAX_DATA_SIZE   (500)
struct packet {                 // 512 Byte Packet to & from Simulator
    unsigned short flags;       // enum packet_type
    unsigned short size;        // real packet data size
    unsigned int seq_number;
    unsigned int ack_number;
    char data[MAX_DATA_SIZE];
};

struct p_event {                // Event Structure
    enum proto_event event;
    struct packet packet;
    int size;               // event data size
};

enum proto_state c_state = LISTEN;         // Initial State
volatile int timedout = 0;

static void timer_handler(int signum)
{
    printf("Timedout\n");
    timedout = 1;
}

static void timer_init(void)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void set_timer(int sec)
{
    struct itimerval timer;

    timedout = 0;
    timer.it_value.tv_sec = sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;   // Non Periodic timer
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, NULL);
}

int initial_seq_number;
int received_size;

int data_count;
int current_seq_number;
int next_seq_number;

struct packet send_buffer[SEND_BUFFER_SIZE];

void send_packet(int flags, void *p, int size)
{
    struct packet pkt;

    printf("SEND PACKET");

    if (flags) {
        printf(" :");
        if (flags & F_ACK) printf(" F_ACK");
        if (flags & F_SYN) printf(" F_SYN");
        if (flags & F_FIN) printf(" F_FIN");
    }
    printf("\n");

    pkt.flags = flags;
    pkt.size = size;

    if (size) {
        memcpy(pkt.data, ((struct p_event *)p)->packet.data, (size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : size);
        pkt.seq_number = ((struct p_event *)p)->packet.seq_number;
        pkt.size = (size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : size;
    }

    if (flags & F_ACK) {
        pkt.ack_number = ((struct p_event *)p)->packet.seq_number + ((struct p_event *)p)->packet.size;
    }

    if (flags & F_SYN) {
        pkt.seq_number = current_seq_number;
        pkt.size = 1;
    }

    if (pkt.size) {
    	next_seq_number = pkt.seq_number + pkt.size;
    }

    Send((char *)&pkt, sizeof(struct packet) - MAX_DATA_SIZE + size);
}

static void report_connect(void *p)
{
    set_timer(0);           // Stop Timer
    printf("Connection established\n");
}

static void active_con(void *p)
{
    send_packet(F_SYN, NULL, 0);
    set_timer(CONNECT_TIMEOUT);
}

static void passive_con(void *p)
{
    send_packet((F_SYN | F_ACK), (struct p_event *)p, 0);
    set_timer(CONNECT_TIMEOUT);
}

static void receive_synack(void *p)
{
    send_packet(F_ACK, (struct p_event *)p, 0);
    report_connect(NULL);
}

static void close_con(void *p)
{
    send_packet(F_FIN, NULL, 0);
    printf("Connection closed\n");
}

static void send_data(void *p)
{
    if (((struct p_event*)p)->event == SEND) {
        memcpy(send_buffer[0].data, ((struct p_event*)p)->packet.data, ((struct p_event*)p)->size);
        send_buffer[0].seq_number = ((struct p_event *)p)->packet.seq_number;
    } else {
        memcpy(((struct p_event*)p)->packet.data, send_buffer[0].data, ((struct p_event*)p)->size);
        ((struct p_event *)p)->packet.seq_number = send_buffer[0].seq_number;
    }

    ((struct p_event*)p)->size = strlen(((struct p_event*)p)->packet.data) + 1;

    printf("Send data to peer: data='%s' size=%d seq_number=%d\n",
        ((struct p_event*)p)->packet.data, ((struct p_event*)p)->size, ((struct p_event *)p)->packet.seq_number);
    send_packet(F_DATA, (struct p_event *)p, ((struct p_event *)p)->size);

    set_timer(SEND_TIMEOUT);
}

static void save_data(void *p)
{
    printf("Data %d-%d saved: data='%s', received_size=%d\n",
        ((struct p_event*)p)->packet.seq_number - (initial_seq_number + 1),
        ((struct p_event*)p)->packet.seq_number - (initial_seq_number + 1) + ((struct p_event*)p)->packet.size - 1,
        ((struct p_event*)p)->packet.data, received_size);
}

static void receive_data(void *p)
{
    printf("Data arrived: size=%d seq_number=%d\n",
        ((struct p_event*)p)->packet.size, ((struct p_event*)p)->packet.seq_number);

    if (((initial_seq_number + 1) + received_size) == ((struct p_event*)p)->packet.seq_number) {
        save_data((struct p_event *)p);
        received_size += ((struct p_event*)p)->packet.size;
    } else {
        printf("Data ignored\n");
    }

    // make error in ACK
    // ((struct p_event *)p)->packet.seq_number-=rand()%2;

    send_packet(F_ACK, (struct p_event *)p, 0);
}

static void receive_ack(void *p)
{
    printf("ACK received: ack_number=%d\n",
        ((struct p_event*)p)->packet.ack_number);

    set_timer(0);           // Stop Timer
}

struct state_action p_FSM[NUM_STATE][NUM_EVENT] = {
  //  for each event:
  //  RCV_SYN,						RCV_FIN,				RCV_ACK,							RCV_DATA,
  //  CONNECT,						CLOSE,					SEND,								TIMEOUT


  // - LISTEN state
    {{ passive_con,	SYN_RECEIVED },	{ NULL,	LISTEN },		{ NULL,	LISTEN },					{ NULL,	LISTEN },
     { active_con,	SYN_SENT	 },	{ NULL,	LISTEN },		{ NULL,	LISTEN },					{ NULL,	LISTEN }},

  // - SYN-SENT state
    {{ NULL, SYN_SENT },			{ close_con, LISTEN },	{ receive_synack,	ESTABLISHED	},	{ NULL,		 SYN_SENT },
     { NULL, SYN_SENT },			{ close_con, LISTEN },	{ NULL,				SYN_SENT	},	{ close_con, LISTEN	  }},

  // - SYN-RECEIVED state
    {{ NULL, SYN_RECEIVED },		{ close_con, LISTEN },	{ report_connect, 	ESTABLISHED	 },	{ NULL,		 SYN_RECEIVED },
     { NULL, SYN_RECEIVED },		{ close_con, LISTEN },	{ NULL, 			SYN_RECEIVED },	{ close_con, LISTEN		  }},

  // - ESTABLISHED state
    {{ NULL, ESTABLISHED },			{ close_con, LISTEN },	{ NULL,				ESTABLISHED	},	{ receive_data, ESTABLISHED },
     { NULL, ESTABLISHED },			{ close_con, LISTEN },	{ send_data,		SENDING		},	{ NULL,			ESTABLISHED }},

  // - SENDING state
    {{ NULL, ESTABLISHED },			{ close_con, LISTEN },	{ receive_ack,		ESTABLISHED	},	{ receive_data, ESTABLISHED },
     { NULL, ESTABLISHED },			{ close_con, LISTEN },	{ send_data,		SENDING		},	{ send_data,	SENDING }},
};

struct p_event *get_event(void)
{
    static struct p_event event;    // not thread-safe

loop:
    // Check if there is user command
    if (!kbhit()) {
        // Check if timer is timed-out
        if(timedout) {
            timedout = 0;
            event.event = TIMEOUT;
        } else {
            // Check Packet arrival by event_wait()
            ssize_t n = Recv((char*)&event.packet, sizeof(struct packet));
            if (n > 0) {
                // if then, decode header to make event

                if (event.packet.flags & F_SYN) {
                    printf("SYN: set initial_seq_number=%d\n", event.packet.seq_number);
                    initial_seq_number = event.packet.seq_number;
                }

                if (event.packet.flags & F_ACK) {
                    if(event.packet.ack_number != next_seq_number) {
                        printf("ACK ignored: expected=%d, but received=%d\n", next_seq_number, event.packet.ack_number);
                        goto loop;
                    }
                    current_seq_number = event.packet.ack_number;
                }

                switch (event.packet.flags) {
                    case F_SYN:
                        event.event = RCV_SYN;
                        break;
                    case F_ACK:
                        data_count++;
                    case F_SYN | F_ACK:
                        event.event = RCV_ACK;
                        break;
                    case F_FIN:
                        event.event = RCV_FIN;
                        break;
                    case F_DATA:
                        event.event = RCV_DATA;
                        event.size = event.packet.size;
                        break;
                    default:
                        goto loop;
                }
            } else
                goto loop;
        }
    } else {
        int n = getchar();
        switch (n) {
            case '0':
                event.event = CONNECT;
                break;
            case '1':
                event.event = CLOSE;
                break;
            case '2':
                event.event = SEND;
                event.packet.seq_number = current_seq_number;
                sprintf(event.packet.data, "%09d", data_count);   // create data
                event.size = strlen(event.packet.data) + 1;
                break;
            case '3':
                return NULL;  // QUIT
            default:
                goto loop;
        }
    }
    return &event;
}

void
Protocol_Loop(void)
{
    struct p_event *eventp;

    data_count = 0;
    received_size = 0;

    srand(time(NULL));
    current_seq_number = next_seq_number = rand(); // initial sequence number
    printf("my initial_seq_number: %d\n", current_seq_number);

    timer_init();
    while (1) {
        printf("\nCurrent State = %s\n", st_name[c_state]);

        /* Step 0: Get Input Event */
        if((eventp = get_event()) == NULL)
            break;
        printf("EVENT : %s\n",ev_name[eventp->event]);
        /* Step 1: Do Action */
        if (p_FSM[c_state][eventp->event].action)
            p_FSM[c_state][eventp->event].action(eventp);
        else
            printf("No Action for this event\n");

        /* Step 2: Set Next State */
        c_state = p_FSM[c_state][eventp->event].next_state;
    }
}

int
main(int argc, char *argv[])
{
    ChannelNumber channel;
    ID id;
    int rateOfPacketLoss;

    printf("Channel : ");
    scanf("%d",&channel);
    printf("ID : ");
    scanf("%d",&id);
    printf("Rate of Packet Loss (0 ~ 100)%% : ");
    scanf("%d",&rateOfPacketLoss);
    if (rateOfPacketLoss < 0)
        rateOfPacketLoss = 0;
    else if (rateOfPacketLoss > 100)
        rateOfPacketLoss = 100;
        
    // Login to SIMULATOR

    if (Login(channel, id, rateOfPacketLoss) == -1) {
        printf("Login Failed\n");
        return -1;
    }

    printf("Entering protocol loop...\n");
    printf("type number '[0]CONNECT', '[1]CLOSE', '[2]SEND', or '[3]QUIT'\n");
    Protocol_Loop();

    // SIMULATOR_CLOSE

    return 0;
}


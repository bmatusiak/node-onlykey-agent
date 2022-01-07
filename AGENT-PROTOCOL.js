
module.exports = {
    //https://github.com/openssh/libopenssh/blob/master/ssh/PROTOCOL.agent

    //Requests from client to agent for protocol 1 key operations

	SSH_AGENTC_REQUEST_RSA_IDENTITIES		    :1,
	SSH_AGENTC_RSA_CHALLENGE			        :3,
	SSH_AGENTC_ADD_RSA_IDENTITY			        :7,
	SSH_AGENTC_REMOVE_RSA_IDENTITY			    :8,
	SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	    :9,
	SSH_AGENTC_ADD_RSA_ID_CONSTRAINED		    :24,

    //Requests from client to agent for protocol 2 key operations

	SSH2_AGENTC_REQUEST_IDENTITIES			    :11,
	SSH2_AGENTC_SIGN_REQUEST			        :13,
	SSH2_AGENTC_ADD_IDENTITY			        :17,
	SSH2_AGENTC_REMOVE_IDENTITY			        :18,
	SSH2_AGENTC_REMOVE_ALL_IDENTITIES		    :19,
	SSH2_AGENTC_ADD_ID_CONSTRAINED			    :25,

    //Key-type independent requests from client to agent

	SSH_AGENTC_ADD_SMARTCARD_KEY			    :20,
	SSH_AGENTC_REMOVE_SMARTCARD_KEY			    :21,
	SSH_AGENTC_LOCK					            :22,
	SSH_AGENTC_UNLOCK			    	        :23,
	SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED	:26,

    //Generic replies from agent to client

	SSH_AGENT_FAILURE				            :5,
	SSH_AGENT_SUCCESS				            :6,

    //Replies from agent to client for protocol 1 key operations

	SSH_AGENT_RSA_IDENTITIES_ANSWER	            :2,
	SSH_AGENT_RSA_RESPONSE				        :4,

    //Replies from agent to client for protocol 2 key operations

	SSH2_AGENT_IDENTITIES_ANSWER			    :12,
	SSH2_AGENT_SIGN_RESPONSE			        :14,

    //Key constraint identifiers

	SSH_AGENT_CONSTRAIN_LIFETIME			    :1,
	SSH_AGENT_CONSTRAIN_CONFIRM			        :2,
	
}

/*
      SSH_MSG_USERAUTH_REQUEST            50
      SSH_MSG_USERAUTH_FAILURE            51
      SSH_MSG_USERAUTH_SUCCESS            52
      SSH_MSG_USERAUTH_BANNER             53
      SSH_MSG_USERAUTH_PK_OK              60
      SSH_MSG_USERAUTH_PASSWD_CHANGEREQ   60

*/

/*CLIENT

var PROTOCOL = {
  SSH_AGENTC_REQUEST_RSA_IDENTITIES: 11,
  SSH_AGENT_IDENTITIES_ANSWER: 12,
  SSH2_AGENTC_SIGN_REQUEST: 13,
  SSH2_AGENT_SIGN_RESPONSE: 14,
  SSH_AGENT_FAILURE: 5,
  SSH_AGENT_SUCCESS: 6
};


*/


/*SERVER


    SSH_AGENTC_REQUEST_IDENTITIES                  11
    SSH_AGENTC_SIGN_REQUEST                        13
    SSH_AGENTC_ADD_IDENTITY                        17
    SSH_AGENTC_REMOVE_IDENTITY                     18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES               19
    SSH_AGENTC_ADD_ID_CONSTRAINED                  25
    SSH_AGENTC_ADD_SMARTCARD_KEY                   20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY                21
    SSH_AGENTC_LOCK                                22
    SSH_AGENTC_UNLOCK                              23
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       26
    SSH_AGENTC_EXTENSION                           27
    
    The following numbers are used for replies from the agent to the client.

    SSH_AGENT_FAILURE                               5
    SSH_AGENT_SUCCESS                               6
    SSH_AGENT_EXTENSION_FAILURE                     28
    SSH_AGENT_IDENTITIES_ANSWER                     12
    SSH_AGENT_SIGN_RESPONSE                         14
    
    The following numbers are used to identify key constraints. These are only used in key constraints and are not sent as message numbers.
    
    SSH_AGENT_CONSTRAIN_LIFETIME                    1
    SSH_AGENT_CONSTRAIN_CONFIRM                     2
    SSH_AGENT_CONSTRAIN_EXTENSION                   3
    
    The following numbers may be present in signature request (SSH_AGENTC_SIGN_REQUEST) messages. These flags form a bit field by taking the logical OR of zero or more flags.

    SSH_AGENT_RSA_SHA2_256                          2
    SSH_AGENT_RSA_SHA2_512                          4
    
    var PROTOCOL = {
      SSH_AGENTC_REQUEST_RSA_IDENTITIES: 11,
      SSH_AGENT_IDENTITIES_ANSWER: 12,
      SSH2_AGENTC_SIGN_REQUEST: 13,
      SSH2_AGENT_SIGN_RESPONSE: 14,
      SSH_AGENT_FAILURE: 5,
      SSH_AGENT_SUCCESS: 6
    };

*/


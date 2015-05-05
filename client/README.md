	'/server'
		REQUEST
			
		ACK
			server_pk_n
			server_pk_e

	'/reserve'
		REQUEST
			nonce
			signature
			blinded_nonce
			slot_id
			blinded_deletion_nonce

		ACK
			success (True, False)
			blinded_sign
			blinded_deletion_sign

	'/push'
		REQUEST
			nonce
			signature
			blinded_nonce
			slot_id
			message

		ACK
			blinded_sign

	'/subscribe'
		REQUEST
			blinded_nonce
			client_username
			client_pk_n
			client_pk_e
			client_sign_pk_n
			client_sign_pk_e

		ACK
			blinded_sign
			user
				client_user_id
				client_username
				client_pk_n
				client_pk_e
				client_sign_pk_n
				client_sign_pk_e

	'/update_user_table'
		REQUEST
			nonce
			signature
			blinded_nonce
			client_user_table_ptr

		ACK
			new_users ([user ... user])
			blinded_sign

	'/pull'
		REQUEST
			nonce
			signature
			blinded_nonce
			slot_id

		ACK
			blinded_sign
			messages ([message ... message])

	'/delete'
		REQUEST
			nonce
			signature
			blinded_nonce
			slot_id

		ACK
			blinded_sign

	'/initiate'
		REQUEST
			nonce
			signature
			blinded_nonce
			message

		ACK
			blinded_sign

	'/update_new_conversation_table'
		REQUEST
			nonce
			signature
			blinded_nonce
			client_new_converstations_table_ptr

		ACK
			blinded_sig
			new_conversations ([message ... message])
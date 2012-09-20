
def calculate_social_distance(peer_interaction, twitter = None, email = None, facebook = None):
		
	social_distances = {}		
	
	if twitter == True:
		
		altruism_level = {}	
		total = 0.0
		peers = []
	
		for tag in peer_interaction:
			for peer in peer_interaction[tag]:
				peers.append(peer)
				social_distances[peer] = -1
		
		for peer in peers:
			altruism_level[peer] = min(peer_interaction['retweets_of_me'][peer], peer_interaction['retweeted_by_me'][peer]) + min(peer_interaction['dm_to_me'][peer], peer_interaction['dm_by_me'][peer]) + min(peer_interaction['mentions_to_me'][peer], peer_interaction['mentions_by_me'][peer])
			total = total + altruism_level[peer]
				
		if total > 0:
			for peer in altruism_level:
				altruism_level[peer] = altruism_level[peer] / total
					
			for peer in peers:
				social_distances[peer] = 1.0 / altruism_level[peer] if altruism_level[peer] > 0 else -1
	
	elif email == True or facebook == True:
		
		activity = 0
		
		for peer in peer_interaction:
			if peer_interaction[peer] != -1:
				activity += peer_interaction[peer]
		
		if activity > 0:		
			for peer in peer_interaction:
				if peer_interaction[peer] > 0.0:
					social_distances[peer] = (activity + .0) / peer_interaction[peer]
				else:
					social_distances[peer] = -1
		
				
	return social_distances
	
def calculate_multihop(peer_interaction, social_distances, twitter = None, email = None):
	
	multihop = { }
	
	if twitter == True:
		for peer in peer_interaction:
			inte = 0
			
			for indpeer in peer_interaction[peer]:
				if peer_interaction[peer][indpeer] != -1:
					inte += peer_interaction[peer][indpeer]
					
			for indpeer in peer_interaction[peer]:
				partial = -1

				if peer_interaction[peer][indpeer] != -1:
					partial = (.0 + inte) / peer_interaction[peer][indpeer]
					
					if peer in social_distances and social_distances[peer] > 0:
						if partial > 0:
							if indpeer in multihop and multihop[peer] > 0:
								multihop[indpeer] = min (partial * social_distances[peer] * 1.1, multihop[indpeer])
							else:
								multihop[indpeer] = partial * social_distances[peer] * 1.1						
				else:
					multihop[indpeer] = -1
					
	return multihop

"""
Module for getting Facebook peers and posts.
Requires installing pythonforfacebook SDK (http://www.pythonforfacebook.com/).
It is available via pip:
pip install facebook-sdk

Or via github:
pip install -e git+git://github.com/pythonforfacebook/facebook-sdk.git#egg=facebook-sdk

Also requires requests module:
pip install requests
"""

# Standard python library
from collections import deque

import facebook
import requests

def filter_post(post):
    """ Get the poster and post target; get the post's created date. """
    filtered = {post['from']['id']: post['created_time']}
    return filtered


def main():
    # One could use a temporary access token, such as those for use with Graph API Explorer.
    # They have a short lifetime in hours, countable using just hands and feet at most.
    access_token='<valid access token is required>'
    graph = facebook.GraphAPI(access_token=access_token
        #facebook.get_app_access_token(
        #app_id='<valid app id required>',
        #app_secret='<valid app secret required>')
    )
    # TODO: get a longer-lasting token to use (in theory the app_id and app_secret should do that,
    # but using them I could not use the user ids.)

    filtered_posts = {}
    user_queue = deque()
    visited = set()
    # Requires a valid Facebook user id. Could use Graph API Explorer to find it for 'me'.
    visited.add('<valid Facebook user id required>')
    user_queue.append('<valid Facebook user id required>')
    # TODO: maybe utilize SocialDistance to determine what the maximum level should be
    # (but, could result in too tightly-coupled code)
    # TODO: perhaps due to the Graph API Explorer token, or perhaps because we need to
    # get user's permissions to collect their data, using max_depth=10 causes an
    # Unsupported operation error. max_depth=1 works, as does max_depth=2
    max_depth = 2
    count = 0
    while user_queue:
        user = user_queue.popleft()
        if count > max_depth:
            break
        filtered_posts.update(get_posts(graph, user))
        friends = get_friends(graph, user)
        for friend in friends:
            if friend not in visited:
                visited.add(friend)
                user_queue.append(friend)
        count += 1
    # End BFS search of user and their friends
    # TODO: filter posts based on a date range
    # TODO: create node.Node objects from filtered_posts, etc.
    print filtered_posts

def get_friends(graph, user):
    all_friends = []
    profile = graph.get_object(user)
    friends = graph.get_connections(profile['id'], 'friends')
    done = False
    while not done:
        try:
            all_friends.extend([f['id'] for f in friends['data']])
            # TODO: using a Graph API Explorer access token appears to limit this list severely;
            # the 'next' url goes to offset 5000 with limit 5000.
            friends = requests.get(friends['paging']['next']).json()
        except KeyError:
            done = True
    return all_friends

def get_posts(graph, user):
    filtered_posts = {}
    profile = graph.get_object(user)
    posts = graph.get_connections(profile['id'], 'posts')
    done = False
    while not done:
        try:
            filtered = [filter_post(post) for post in posts['data']]
            if user not in filtered_posts:
                filtered_posts[user] = []
            filtered_posts[user].extend(filtered)
            posts = requests.get(posts['paging']['next']).json()
        except KeyError:
            done = True
    return filtered_posts


if __name__ == '__main__':
    main()
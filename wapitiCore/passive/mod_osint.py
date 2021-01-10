from wapitiCore.passive.passive import Analysis, Result
from wapitiCore.language.vulnerability import _, Additional
import re

class mod_osint(Analysis):
    """This class implements an osint module which can retrieve emails"""

    name = "osint"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)

    def analyse(self, page):
        if page.base_url not in self.pages:
            self.pages.append(page.base_url)
            regexp_mail = r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")(?:@| ?\[at\] ?)(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
            mails = re.findall(regexp_mail, page.content)
            for i in mails:
                yield Result(Additional.INFO_OSINT_EMAIL.format(i), Additional.MSG_OSINT, page.base_url, type="additional")

            regexp_social = re.compile(r"(?P<angellist__company>(?:https?:)?\/\/angel\.co\/company\/(?P<angellist__company__company>[A-z0-9_-]+)(?:\/(?P<angellist__company__company_subpage>[A-z0-9-]+))?)|(?P<angellist__job>(?:https?:)?\/\/angel\.co\/company\/(?P<angellist__job__company>[A-z0-9_-]+)\/jobs\/(?P<angellist__job__job_permalink>(?P<angellist__job__job_id>[0-9]+)-(?P<angellist__job__job_slug>[A-z0-9-]+)))|(?P<angellist__user>(?:https?:)?\/\/angel\.co\/(?P<angellist__user__type>u|p)\/(?P<angellist__user__user>[A-z0-9_-]+))|(?P<email__mailto>mailto:(?P<email__mailto__email>[A-z0-9_.+-]+@[A-z0-9_.-]+\.[A-z]+))|(?P<facebook__profile>(?:https?:)?\/\/(?:www\.)?(?:facebook|fb)\.com\/(?P<facebook__profile__profile>(?![A-z]+\.php)(?!marketplace|gaming|watch|me|messages|help|search|groups)[A-z0-9_\-\.]+)\/?)|(?P<facebook__profile_by_id>(?:https?:)?\/\/(?:www\.)facebook.com/(?:profile.php\?id=)?(?P<facebook__profile_by_id__id>[0-9]+))|(?P<github__repo>(?:https?:)?\/\/(?:www\.)?github\.com\/(?P<github__repo__login>[A-z0-9_-]+)\/(?P<github__repo__repo>[A-z0-9_-]+)\/?)|(?P<github__user>(?:https?:)?\/\/(?:www\.)?github\.com\/(?P<github__user__login>[A-z0-9_-]+)\/?)|(?P<google_plus__user_id>(?:https?:)?\/\/plus\.google\.com\/(?P<google_plus__user_id__id>[0-9]{21}))|(?P<google_plus__username>(?:https?:)?\/\/plus\.google\.com\/\+(?P<google_plus__username__username>[A-z0-9+]+))|(?P<hackernews__item>(?:https?:)?\/\/news\.ycombinator\.com\/item\?id=(?P<hackernews__item__item>[0-9]+))|(?P<hackernews__user>(?:https?:)?\/\/news\.ycombinator\.com\/user\?id=(?P<hackernews__user__user>[A-z0-9_-]+))|(?P<instagram__profile>(?:https?:)?\/\/(?:www\.)?(?:instagram\.com|instagr\.am)\/(?P<instagram__profile__username>[A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?))|(?P<linkedin__company>(?:https?:)?\/\/(?:[\w]+\.)?linkedin\.com\/company\/(?P<linkedin__company__company_permalink>[A-z0-9-\.]+)\/?)|(?P<linkedin__post>(?:https?:)?\/\/(?:[\w]+\.)?linkedin\.com\/feed\/update\/urn:li:activity:(?P<linkedin__post__activity_id>[0-9]+)\/?)|(?P<linkedin__profile>(?:https?:)?\/\/(?:[\w]+\.)?linkedin\.com\/in\/(?P<linkedin__profile__permalink>[\w\-\_À-ÿ%]+)\/?)|(?P<linkedin__profile_pub>(?:https?:)?\/\/(?:[\w]+\.)?linkedin\.com\/pub\/(?P<linkedin__profile_pub__permalink_pub>[A-z0-9_-]+)(?:\/[A-z0-9]+){3}\/?)|(?P<medium__post>(?:https?:)?\/\/medium\.com\/(?:(?:@(?P<medium__post__username>[A-z0-9]+))|(?P<medium__post__publication>[a-z-]+))\/(?P<medium__post__slug>[a-z0-9\-]+)-(?P<medium__post__post_id>[A-z0-9]+)(?:\?.*)?)|(?P<medium__post_of_subdomain_publication>(?:https?:)?\/\/(?P<medium__post_of_subdomain_publication__publication>(?!www)[a-z-]+)\.medium\.com\/(?P<medium__post_of_subdomain_publication__slug>[a-z0-9\-]+)-(?P<medium__post_of_subdomain_publication__post_id>[A-z0-9]+)(?:\?.*)?)|(?P<medium__user>(?:https?:)?\/\/medium\.com\/@(?P<medium__user__username>[A-z0-9]+)(?:\?.*)?)|(?P<medium__user_by_id>(?:https?:)?\/\/medium\.com\/u\/(?P<medium__user_by_id__user_id>[A-z0-9]+)(?:\?.*))|(?P<reddit__user>(?:https?:)?\/\/(?:[a-z]+\.)?reddit\.com\/(?:u(?:ser)?)\/(?P<reddit__user__username>[A-z0-9\-\_]*)\/?)|(?P<skype__profile>(?:(?:callto|skype):)(?P<skype__profile__username>[a-z][a-z0-9\.,\-_]{5,31})(?:\?(?:add|call|chat|sendfile|userinfo))?)|(?P<snapchat__profile>(?:https?:)?\/\/(?:www\.)?snapchat\.com\/add\/(?P<snapchat__profile__username>[A-z0-9\.\_\-]+)\/?)|(?P<stackexchange__user>(?:https?:)?\/\/(?:www\.)?stackexchange\.com\/users\/(?P<stackexchange__user__id>[0-9]+)\/(?P<stackexchange__user__username>[A-z0-9-_.]+)\/?)|(?P<stackexchange_network__user>(?:https?:)?\/\/(?:(?P<stackexchange_network__user__community>[a-z]+(?!www))\.)?stackexchange\.com\/users\/(?P<stackexchange_network__user__id>[0-9]+)\/(?P<stackexchange_network__user__username>[A-z0-9-_.]+)\/?)|(?P<stackoverflow__question>(?:https?:)?\/\/(?:www\.)?stackoverflow\.com\/questions\/(?P<stackoverflow__question__id>[0-9]+)\/(?P<stackoverflow__question__title>[A-z0-9-_.]+)\/?)|(?P<stackoverflow__user>(?:https?:)?\/\/(?:www\.)?stackoverflow\.com\/users\/(?P<stackoverflow__user__id>[0-9]+)\/(?P<stackoverflow__user__username>[A-z0-9-_.]+)\/?)|(?P<telegram__profile>(?:https?:)?\/\/(?:t(?:elegram)?\.me|telegram\.org)\/(?P<telegram__profile__username>[a-z0-9\_]{5,32})\/?)|(?P<twitter__status>(?:https?:)?\/\/(?:[A-z]+\.)?twitter\.com\/@?(?P<twitter__status__username>[A-z0-9_]+)\/status\/(?P<twitter__status__tweet_id>[0-9]+)\/?)|(?P<twitter__user>(?:https?:)?\/\/(?:[A-z]+\.)?twitter\.com\/@?(?P<twitter__user__username>[A-z0-9_]+)\/?)|(?P<vimeo__user>(?:https?:)?\/\/vimeo\.com\/user(?P<vimeo__user__id>[0-9]+))|(?P<vimeo__video>(?:https?:)?\/\/(?:(?:www)?vimeo\.com|player.vimeo.com\/video)\/(?P<vimeo__video__id>[0-9]+))|(?P<youtube__channel>(?:https?:)?\/\/(?:[A-z]+\.)?youtube.com\/channel\/(?P<youtube__channel__id>[A-z0-9-\_]+)\/?)|(?P<youtube__user>(?:https?:)?\/\/(?:[A-z]+\.)?youtube.com\/user\/(?P<youtube__user__username>[A-z0-9]+)\/?)|(?P<youtube__video>(?:https?:)?\/\/(?:(?:www\.)?youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)(?P<youtube__video__id>[A-z0-9\-\_]+))")
            social_dicts = [i.groupdict() for i in regexp_social.finditer(page.content)]
            for d in social_dicts:
                for type, link in d.items():
                    if link is not None:
                        yield Result(Additional.INFO_OSINT_LINK.format(type, link), Additional.MSG_OSINT, page.base_url, type="additional")
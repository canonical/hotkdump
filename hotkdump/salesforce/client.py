import logging

from simple_salesforce import Salesforce
from simple_salesforce import exceptions as sf_exceptions
from oslo_config import cfg


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

salesforce_opts = [
    cfg.StrOpt('username',
               help='Username used to connect to Salesforce. '
                    'Used with password-based login'),
    cfg.StrOpt('password',
               secret=True,
               help='Password used to connect to Salesforce. '
                    'Used with password-based login'),
    cfg.HostAddressOpt('instance',
                       default='canonical--obiwan.my.salesforce.com',
                       help='Domain name of the salesforce instance. '
                            'Used with password or OAuth login'),
    cfg.StrOpt('security_token',
               help='Security token used to connect to Salesforce. '
                    'Used with password-based login'),
    cfg.StrOpt('access_token',
               help='Access token used to connect to Salesforce. '
                    'Used with OAuth-based login'),
    cfg.StrOpt('client_id',
               help='Client id to use when connecting to salesforce.'),
    cfg.StrOpt('domain',
               default='test',
               help='Domain for authentication. Use test for connecting to '
                    'sandboxes, and login for connecting to production. '
                    'Used with password-based login'),
        ]

CONF.register_opts(salesforce_opts, 'salesforce')


class SalesforceClient(object):
    """
    Used to talk with Salesforce.
    """

    def __init__(self, username=None, password=None, instance=None,
                 security_token=None, access_token=None, client_id=None,
                 domain=None):
        self.username = username or CONF.salesforce.username
        self.password = password or CONF.salesforce.password
        self.instance = instance or CONF.salesforce.instance
        self.security_token = security_token or CONF.salesforce.security_token
        self.access_token = access_token or CONF.salesforce.access_token
        self.client_id = client_id or CONF.salesforce.client_id
        self.domain = domain or CONF.salesforce.domain
        self._client = None

    @property
    def client(self):
        if self._client is not None:
            return self._client

        if not self.client_id:
            raise RuntimeError('Missing required configuration parameter '
                               '"client_id"')

        params = {
            'instance': self.instance,
            'client_id': self.client_id
        }

        if self.security_token:
            params.update({
                'username': self.username,
                'password': self.password,
                'security_token': self.security_token,
                'domain': self.domain,
                })
        elif self.access_token:
            params.update({
                'instance': self.instance,
                'session_id': self.access_token,
                })
        else:
            raise RuntimeError('salesforce: security_token or access_token '
                               'required')

        try:
            # TODO(joalif) - Confirm whether Salesforce performs authentication
            # in its constructor or if it delegates unitl first call.
            LOG.info("Going to connect to sf")
            self._client = Salesforce(**params)
        except sf_exceptions.SalesforceAuthenticationFailed:
            LOG.error("Salesforce authentication failed")
            raise
        except sf_exceptions.SalesforceExpiredSession:
            LOG.error("Salesforce expired session")
            raise
        except Exception:
            LOG.exception("Unexpected exception")
            raise
        else:
            return self._client

    def _query(self, query):
        """
        Queries salesforce.
        """
        try:
            LOG.info("Making query: %s", query)
            return self.client.query(query)
        except Exception:
            LOG.exception("Exception while quering salesforce")
            raise

    def post_comment_to_sf(self, case_num, comment):
        """
        Make a comment to salesforce case.
        """
        if not comment:
            raise RuntimeError('Empty comment to post.')

        query_str = ("SELECT Case.Id, Case.CaseNumber, Case.IsClosed FROM"
                     " Case WHERE CaseNumber='%s'")
        query_str = query_str % case_num
        results = self._query(query_str)
        records = results['records']
        if len(records) != 1:
            LOG.error("Query %s return %d recods.", query_str, len(records))
            return

        # TODO(joalif) - check valid case_num
        # post comment
        results = self.client.CaseComment.create({
            'ParentId': results['records'][0]['Id'],
            'CommentBody': comment,
            'IsPublished': False
            })
        LOG.info(results)
        if not results['success']:
            LOG.warning('Unable to post comment on case %s: %s',
                        case_num, results['erros'])
        else:
            LOG.info('Commented on case %s' % case_num)

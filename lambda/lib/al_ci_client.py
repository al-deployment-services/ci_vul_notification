from CIAuth import CIAuth

class CloudInsight(CIAuth):
    def __init__(self, args):
        self.service = "launcher"
        CIAuth.__init__(self,args)

    def get_launcher_status(self):
        self.service = "launcher"
        return self.query(self.service, [self.account_id, "environments", self.environment_id])

    def get_launcher_resource(self):
        self.service = "launcher"
        return self.query(self.service, [self.account_id, "resources"])

    def get_environments(self):
        self.service = "environments"
        return self.query(self.service, [self.account_id, self.environment_id])

    def get_environments_by_cid(self):
        self.service = "environments"
        return self.query(self.service, [self.account_id])

    def get_environments_by_cid_custom(self, query_args=None):
        self.service = "environments"
        return self.query(self.service, [self.account_id], query_args)

    def get_asset_custom(self, query_args=None):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "assets"], query_args)

    def get_remediations(self):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"])

    def get_remediations_short(self):
        self.service = "assets"
        query_args={}
        query_args['include_filters'] = 'false'
        query_args['include_remediations'] = 'true'
        query_args['details'] = 'false'
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"], query_args)

    def get_remediations_custom(self, query_args=None):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"], query_args)

    def get_all_child(self):
        self.service = "aims"
        query_args={}
        query_args['active'] = 'true'
        return self.query(self.service, [self.account_id, "accounts", "managed"], query_args)

    def get_vulnerability_map(self):
        self.service = "vulnerability"
        return self.query(self.service, [])

    def get_vulnerability_map_custom(self, vulnerability_id=None):
        self.service = "vulnerability"
        return self.query(self.service, [vulnerability_id])

    def get_remediations_map_custom(self, remediation_id=None):
        self.service = "remediation"
        return self.query(self.service, [remediation_id])

    def get_scheduler_summary(self):
        self.service = "scheduler"
        return self.query(self.service, [self.account_id, self.environment_id, "summary"])

    def get_user_name_by_id(self, user_id):
        self.service = "aims"
        return self.query(self.service, ["user", user_id])

    def get_cid_details(self, cid=None):
        self.service = "aims"
        if cid != None:
            return self.query(self.service, [cid, "account"])
        else:
            return self.query(self.service, [self.account_id, "account"])

    def get_account_details(self):
        self.service = "aims"
        return self.query(self.service, [self.account_id, "account"])

    def get_account_entitlements(self):
        self.service = "subscriptions"
        return self.query(self.service, [self.account_id, "entitlements"])

    def get_scanmon(self):
        self.service = "scanmon"
        return self.query(self.service, [self.account_id, "environments", self.environment_id])

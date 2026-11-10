ARG GITEA_IMAGE=gitea/gitea:1.16.6@sha256:01e0b118c1c9ebf16c0549d9bf3d12fe0eb31513a25e31007d0d08295e825e33
FROM ${GITEA_IMAGE}
COPY start.sh /opt/module-target-gitea-start.sh
COPY accounts.env /opt/module-target-gitea-accounts.env
ENTRYPOINT ["/bin/sh", "/opt/module-target-gitea-start.sh"]
CMD []

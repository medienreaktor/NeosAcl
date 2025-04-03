<?php

namespace Sandstorm\NeosAcl\Service;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\ContentRepository\Core\DimensionSpace\DimensionSpacePoint;
use Neos\ContentRepository\Core\NodeType\NodeType;
use Neos\ContentRepository\Core\Projection\ContentGraph\Node;
use Neos\ContentRepository\Core\SharedModel\ContentRepository\ContentRepositoryId;
use Neos\ContentRepository\Core\SharedModel\Node\NodeAggregateId;
use Neos\ContentRepository\Core\SharedModel\Workspace\Workspace;
use Neos\ContentRepositoryRegistry\ContentRepositoryRegistry;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\ResourceManagement\ResourceManager;
use Neos\Flow\Security\Context;
use Neos\Neos\Domain\Model\WorkspaceClassification;
use Neos\Neos\Domain\Service\NodeTypeNameFactory;
use Neos\Neos\Domain\Service\WorkspaceService;
use Neos\Neos\FrontendRouting\SiteDetection\SiteDetectionResult;
use Neos\Neos\Service\UserService;
use Sandstorm\NeosAcl\Domain\Dto\MatcherConfiguration;

/**
 * @Flow\Scope("singleton")
 */
class DynamicRoleEditorService {
    /**
     * @Flow\Inject
     * @var ContentRepositoryRegistry
     */
    protected $contentRepositoryRegistry;
    /**
     * @Flow\Inject
     * @var WorkspaceService
     */
    protected $workspaceService;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var ResourceManager
     */
    protected $resourceManager;

    /**
     * @Flow\InjectConfiguration(path="userInterface.navigateComponent.nodeTree.loadingDepth", package="Neos.Neos")
     * @var string
     */
    protected $nodeTreeLoadingDepth;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    public function generatePropsForReactWidget(ActionRequest $actionRequest, ?MatcherConfiguration $dynamicRoleMatcherConfiguration): array {
        $siteDetectionResult = SiteDetectionResult::fromRequest($actionRequest->getHttpRequest());
        $contentRepositoryId = $siteDetectionResult->contentRepositoryId;
        $siteNode = $this->getSiteNode($contentRepositoryId);
        $props = [
            'nodeTypes' => $this->generateNodeTypeNames($contentRepositoryId),
            'nodeSearchEndpoint' => $this->generateNodeSearchEndpoint($actionRequest),
            'siteNodeName' => $siteNode->aggregateId,
            'nodeTreeLoadingDepth' => (int)$this->nodeTreeLoadingDepth,
            'csrfProtectionToken' => $this->securityContext->getCsrfProtectionToken(),
            'cssFilePath' => $this->resourceManager->getPublicPackageResourceUriByPath('resource://Sandstorm.NeosAcl/Public/React/extra-neos-wrapper.css'),
            'workspaces' => $this->getWorkspaces($contentRepositoryId),
            'dimensions' => $this->getDimensionPresets($contentRepositoryId),
            'expandedNodes' => $dynamicRoleMatcherConfiguration ? $this->generateExpandedNodeIdentifiers($dynamicRoleMatcherConfiguration, $siteNode) : [],
        ];

        return ($props);
    }

    private function generateNodeTypeNames(ContentRepositoryId $contentRepositoryId) {
        $contentRepository = $this->contentRepositoryRegistry->get($contentRepositoryId);
        $nodeTypes = [];
        $nodeTypeManager = $contentRepository->getNodeTypeManager();
        /* @var $nodeType NodeType */
        foreach ($nodeTypeManager->getNodeTypes() as $nodeType) {
            $nodeTypes[] = [
                'value' => $nodeType->name,
                'label' => $nodeType->name,
                'isDocumentNode' => $nodeType->isOfType('Neos.Neos:Document')
            ];
        }
        return $nodeTypes;
    }

    private function generateNodeSearchEndpoint(ActionRequest $actionRequest): string {
        $uriBuilder = new UriBuilder();
        $uriBuilder->setRequest($actionRequest->getMainRequest());
        return $uriBuilder->setCreateAbsoluteUri(true)->uriFor('index', [], 'Service\Nodes', 'Neos.Neos');
    }

    protected function getWorkspaces(ContentRepositoryId $contentRepositoryId) {

        $result = [];
        $contentRepository = $this->contentRepositoryRegistry->get($contentRepositoryId);
        $workspaces = $contentRepository->findWorkspaces();
        foreach ($workspaces as $workspace) {
            /* @var $workspace Workspace */
            $workspaceMetadata = $this->workspaceService->getWorkspaceMetadata($contentRepositoryId, $workspace->workspaceName);
            $isPersonal = $workspaceMetadata->classification === WorkspaceClassification::PERSONAL;
            $workspaceName = $workspace->workspaceName->value;
            if (!$isPersonal && $workspaceName !== 'live') {
                $result[] = [
                    'name' => $workspaceName,
                    'label' => $workspaceMetadata->title
                ];
            }
        }

        return $result;
    }

    //TODO: get the label?

    protected function getDimensionPresets(ContentRepositoryId $contentRepositoryId) {
        $result = [];

        $contentRepository = $this->contentRepositoryRegistry->get($contentRepositoryId);
        $dimensions = $contentRepository->getContentDimensionSource()->getContentDimensionsOrderedByPriority();
        foreach ($dimensions as $dimensionName => $dimensionConfig) {
            foreach ($dimensionConfig->getRootValues() as $presetName => $presetConfig) {
                $result[] = [
                    'dimensionName' => $dimensionName,
                    'presetName' => $presetName,
                    'dimensionLabel' => $dimensionConfig['label'],
                    'presetLabel' => $presetConfig->value,
                ];
            }
        }
        return $result;
    }

    public function getSiteNode(ContentRepositoryId $contentRepositoryId): Node {
        $currentUser = $this->userService->getBackendUser();
        $contentRepository = $this->contentRepositoryRegistry->get($contentRepositoryId);
        $workspace = $this->workspaceService->getPersonalWorkspaceForUser($contentRepositoryId, $currentUser->getId());
        $workspaceName =  $workspace->workspaceName;
        $subgraph = $contentRepository->getContentSubgraph($workspaceName, DimensionSpacePoint::createWithoutDimensions());
        $siteNode = $subgraph->findRootNodeByType(NodeTypeNameFactory::forSites());
        return $siteNode;
    }

    private function generateExpandedNodeIdentifiers(MatcherConfiguration $dynamicRoleMatcherConfiguration, Node $siteNode) {
        $nodeContextPaths = [];

        $contentRepository = $this->contentRepositoryRegistry->get($siteNode->contentRepositoryId);
        $subgraph = $contentRepository->getContentSubgraph($siteNode->workspaceName, $siteNode->dimensionSpacePoint);

        foreach ($dynamicRoleMatcherConfiguration->getSelectedNodeIdentifiers() as $nodeIdentifier) {
            $node = $subgraph->findNodeById(NodeAggregateId::fromString($nodeIdentifier));
            $parent = $subgraph->findParentNode($node->aggregateId);
            if ($node && $parent && $node->aggregateId !== $siteNode->aggregateId) {
                // the node itself does not need to be expanded, but all parents should be expanded (so that the node which has the restriction is visible in the tree)
                while ($parent && $parent->aggregateId !== $siteNode->aggregateId) {
                    $node = $subgraph->findParentNode($node->aggregateId);
                    $nodeContextPaths[] = $node->aggregateId;
                }
            }
        }

        return array_values($nodeContextPaths);
    }
}

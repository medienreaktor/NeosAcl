<?php

namespace Sandstorm\NeosAcl\Domain\Dto;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\Flow\Annotations as Flow;
use Doctrine\ORM\Mapping as ORM;

/**
 * The matcher looks as follows:
 *
 * {
 *     "selectedWorkspaces": ["live"], // or empty
 *     "dimensionPresets": ["TODO HOW??"],
 *     "selectedNodes": {
 *       "e35d8910-9798-4c30-8759-b3b88d30f8b5": {
 *         "whitelistedNodeTypes": []
 *       },
 *   }
 *
 * @param array $matcher
 * @return string
 * @Flow\Proxy(false)
 */
class DynamicRoleSelectedNode {
    /**
     * @var string
     */
    protected $nodeIdentifier;

    /**
     * @var array
     */
    protected $whitelistedNodeTypes;

    /**
     * MatcherConfigurationSelectedNode constructor.
     * @param string $nodeIdentifier
     * @param array $whitelistedNodeTypes
     */
    protected function __construct(string $nodeIdentifier, array $whitelistedNodeTypes) {
        $this->nodeIdentifier = $nodeIdentifier;
        $this->whitelistedNodeTypes = $whitelistedNodeTypes;
    }

    public static function fromConfig(string $nodeIdentifier, array $config): self {
        return new self(
            $nodeIdentifier,
            array_values($config['whitelistedNodeTypes'])
        );
    }

    /**
     * @return string
     */
    public function getNodeIdentifier(): string {
        return $this->nodeIdentifier;
    }
}
